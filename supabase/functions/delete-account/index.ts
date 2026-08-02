// Supabase Edge Function: delete-account
//
// Handles account deletion for both buyers and farmers, with real
// safeguards — this is a deliberately careful function since its
// mistakes are irreversible.
//
// Deploy with:  supabase functions deploy delete-account
// No new secrets needed — reuses SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY,
// both already auto-injected (same as send-notification-email).
//
// ── Security model ──
// The caller's identity is NEVER trusted from the request body. It's
// derived server-side from their own JWT (the Authorization header
// Supabase automatically attaches when the client calls this function
// while signed in). This means a user can only ever delete their own
// account — there is no code path where a user ID passed in the body
// could cause someone else's account to be deleted.
//
// ── What actually happens ──
// 1. Identify the caller from their JWT.
// 2. If they're a farmer: re-check server-side that they have no order
//    still in an active state (not delivered/cancelled). This check is
//    NOT trusted from the client — it's redone here, because a malicious
//    client could otherwise call this function directly, skipping the
//    UI's version of this check entirely.
// 3. Check whether this user has ANY order history at all (as buyer or
//    farmer), regardless of status.
//    - None ever: hard-delete the auth user. Whatever happens to the
//      profiles row (cascade or not) is safe, since nothing depends on it.
//    - Some exists: anonymize the profiles row (scrub name/phone/state)
//      but leave the row itself in place, then BAN the auth user
//      (effectively permanent) instead of deleting it — this guarantees
//      they can never log in again, without ever risking a cascade
//      touching the order records those rows are foreign-keyed to.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Effectively permanent — Supabase's ban_duration only accepts a fixed
// duration, not "forever", so 100 years stands in for permanent.
const PERMANENT_BAN = "876000h";

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

Deno.serve(async (req) => {
  try {
    // Identify the caller from their own JWT — this is the only source
    // of truth for "who is asking", never the request body.
    const authHeader = req.headers.get("Authorization") ?? "";
    const callerClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: callerData, error: callerErr } = await callerClient.auth.getUser();
    if (callerErr || !callerData?.user) {
      return new Response(JSON.stringify({ error: "Not authenticated." }), { status: 401 });
    }
    const userId = callerData.user.id;

    // Look up their role and current profile.
    const { data: profile, error: profileErr } = await admin
      .from("profiles")
      .select("id, role")
      .eq("id", userId)
      .single();
    if (profileErr || !profile) {
      return new Response(JSON.stringify({ error: "Profile not found." }), { status: 404 });
    }

    // Farmers: block deletion if any order is still active. Recomputed
    // here server-side regardless of what the client already checked.
    if (profile.role === "farmer") {
      const { count: activeCount, error: activeErr } = await admin
        .from("orders")
        .select("id", { count: "exact", head: true })
        .eq("farmer_id", userId)
        .not("status", "in", "(delivered,cancelled)");
      if (activeErr) {
        return new Response(JSON.stringify({ error: "Could not check active orders: " + activeErr.message }), { status: 500 });
      }
      if ((activeCount ?? 0) > 0) {
        return new Response(
          JSON.stringify({ error: `You still have ${activeCount} active order(s) that aren't delivered or cancelled yet. Please resolve those before deleting your account.` }),
          { status: 400 }
        );
      }
    }

    // Does this user have ANY order history at all, in either role?
    const { count: buyerOrders } = await admin
      .from("orders").select("id", { count: "exact", head: true }).eq("buyer_id", userId);
    const { count: farmerOrders } = await admin
      .from("orders").select("id", { count: "exact", head: true }).eq("farmer_id", userId);
    const hasHistory = (buyerOrders ?? 0) > 0 || (farmerOrders ?? 0) > 0;

    if (!hasHistory) {
      // Nothing depends on this record — safe to fully delete the login.
      const { error: delErr } = await admin.auth.admin.deleteUser(userId);
      if (delErr) {
        return new Response(JSON.stringify({ error: "Could not delete account: " + delErr.message }), { status: 500 });
      }
      return new Response(JSON.stringify({ deleted: true, mode: "hard" }), { status: 200 });
    }

    // Has history — anonymize the profile row (keep it, for the other
    // party's order records) and permanently ban the login instead of
    // deleting it, so there's no risk of a cascade touching orders.
    const { error: anonErr } = await admin
      .from("profiles")
      .update({
        full_name: "Deleted User",
        phone: null,
        state: null,
        is_verified: false,
        verification_status: null,
      })
      .eq("id", userId);
    if (anonErr) {
      return new Response(JSON.stringify({ error: "Could not anonymize profile: " + anonErr.message }), { status: 500 });
    }

    const { error: banErr } = await admin.auth.admin.updateUserById(userId, { ban_duration: PERMANENT_BAN });
    if (banErr) {
      return new Response(JSON.stringify({ error: "Profile was anonymized, but could not disable login: " + banErr.message }), { status: 500 });
    }

    return new Response(JSON.stringify({ deleted: true, mode: "anonymized" }), { status: 200 });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 });
  }
});