// Supabase Edge Function: admin-suspend-user
//
// Lets an admin suspend or unsuspend a farmer or buyer account. Disabling
// a login requires the service role key, which can't safely live in the
// browser — that's the whole reason this needs to be a server-side
// function rather than a direct client-side call.
//
// Deploy with:  supabase functions deploy admin-suspend-user
// No new secrets needed — reuses SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY,
// both already auto-injected (same as the other Edge Functions).
//
// ── Security model (same as delete-account) ──
// The caller's identity — and specifically whether they're actually an
// admin — is NEVER trusted from the request body. It's derived server-side
// from their own JWT, then their role is looked up fresh from the
// database. A non-admin calling this function directly (bypassing the UI
// entirely) gets rejected before anything else runs.
//
// ── What actually happens ──
// Suspend:
//   1. Confirm the caller is a real, currently-authenticated admin.
//   2. Refuse to suspend: yourself, or any other admin account — both are
//      safety guardrails, not the tool for resolving an admin-vs-admin
//      problem.
//   3. Ban the login via Supabase Auth (does NOT delete anything — same
//      "ban_duration" mechanism as account deletion's anonymize path, so
//      there's no risk to any order/review/message history tied to them).
//   4. Record the suspension (who, when, why) on their profile.
//   5. If they're a farmer, deactivate their currently-active listings —
//      so a suspended farmer can't keep receiving new orders while under
//      review. Existing orders are left untouched on purpose; resolving
//      those is a separate, deliberate decision via the dispute tools,
//      not an automatic side effect of suspension.
// Unsuspend:
//   1. Same admin check.
//   2. Lift the ban.
//   3. Record when it was lifted.
//   4. Deliberately does NOT reactivate their listings automatically —
//      that's the farmer's own call to make once they're back.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const PERMANENT_BAN = "876000h"; // ~100 years, same constant as delete-account

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

Deno.serve(async (req) => {
  try {
    const body = await req.json().catch(() => ({}));
    const { targetUserId, action, reason } = body;

    if (!targetUserId || (action !== "suspend" && action !== "unsuspend")) {
      return new Response(JSON.stringify({ error: "Missing or invalid targetUserId/action." }), { status: 400 });
    }
    if (action === "suspend" && (!reason || !String(reason).trim())) {
      return new Response(JSON.stringify({ error: "A reason is required to suspend an account." }), { status: 400 });
    }

    // Identify the caller from their own JWT — never from anything the
    // request body claims.
    const authHeader = req.headers.get("Authorization") ?? "";
    const callerClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: callerData, error: callerErr } = await callerClient.auth.getUser();
    if (callerErr || !callerData?.user) {
      return new Response(JSON.stringify({ error: "Not authenticated." }), { status: 401 });
    }
    const callerId = callerData.user.id;

    const { data: callerProfile, error: callerProfileErr } = await admin
      .from("profiles").select("role").eq("id", callerId).single();
    if (callerProfileErr || !callerProfile || callerProfile.role !== "admin") {
      return new Response(JSON.stringify({ error: "Only admins can do this." }), { status: 403 });
    }

    if (targetUserId === callerId) {
      return new Response(JSON.stringify({ error: "You can't suspend your own account." }), { status: 400 });
    }

    const { data: targetProfile, error: targetErr } = await admin
      .from("profiles").select("id, role").eq("id", targetUserId).single();
    if (targetErr || !targetProfile) {
      return new Response(JSON.stringify({ error: "User not found." }), { status: 404 });
    }
    if (targetProfile.role === "admin") {
      return new Response(JSON.stringify({ error: "Admin accounts can't be suspended through this tool." }), { status: 400 });
    }

    if (action === "suspend") {
      const { error: banErr } = await admin.auth.admin.updateUserById(targetUserId, { ban_duration: PERMANENT_BAN });
      if (banErr) {
        return new Response(JSON.stringify({ error: "Could not disable login: " + banErr.message }), { status: 500 });
      }

      const { error: profileErr } = await admin.from("profiles").update({
        is_suspended: true,
        suspension_reason: String(reason).trim(),
        suspended_at: new Date().toISOString(),
        suspended_by: callerId,
        unsuspended_at: null,
      }).eq("id", targetUserId);
      if (profileErr) {
        return new Response(JSON.stringify({ error: "Login was disabled, but could not update their profile record: " + profileErr.message }), { status: 500 });
      }

      if (targetProfile.role === "farmer") {
        const { error: listingsErr } = await admin
          .from("products").update({ is_active: false })
          .eq("farmer_id", targetUserId).eq("is_active", true);
        if (listingsErr) {
          // Not fatal to the suspension itself — the account is already
          // disabled either way — but worth surfacing so the admin knows
          // to check the farmer's listings manually.
          return new Response(JSON.stringify({
            suspended: true,
            warning: "Account suspended, but couldn't auto-deactivate their listings: " + listingsErr.message,
          }), { status: 200 });
        }
      }

      return new Response(JSON.stringify({ suspended: true }), { status: 200 });
    }

    // action === "unsuspend"
    const { error: unbanErr } = await admin.auth.admin.updateUserById(targetUserId, { ban_duration: "none" });
    if (unbanErr) {
      return new Response(JSON.stringify({ error: "Could not re-enable login: " + unbanErr.message }), { status: 500 });
    }
    const { error: profileErr } = await admin.from("profiles").update({
      is_suspended: false,
      unsuspended_at: new Date().toISOString(),
    }).eq("id", targetUserId);
    if (profileErr) {
      return new Response(JSON.stringify({ error: "Login was re-enabled, but could not update their profile record: " + profileErr.message }), { status: 500 });
    }

    return new Response(JSON.stringify({ unsuspended: true }), { status: 200 });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 });
  }
});
