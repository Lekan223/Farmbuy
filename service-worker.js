// AgroLink Service Worker
// Strategy: cache the app shell (index.html, icons) for offline use,
// network-first for everything else so live data (Supabase) is never stale.

const CACHE_NAME = 'agrolink-v2'; // bumped to force old caches to clear
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png'
];

// ── INSTALL: pre-cache the app shell ──
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

// ── ACTIVATE: clean up ALL old caches immediately ──
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((key) => caches.delete(key)))
    ).then(() => caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)))
  );
  self.clients.claim();
});

// ── FETCH: network-first, fall back to cache when offline ──
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Never intercept Supabase API calls, auth requests, or non-GET requests —
  // these must always hit the network live; caching them would serve
  // stale/broken data (this is almost certainly why "marketplace not
  // loading" type bugs happen with a misconfigured service worker).
  if (
    request.url.includes('supabase.co') ||
    request.url.includes('/auth/') ||
    request.method !== 'GET'
  ) {
    return;
  }

  // For page navigations (loading index.html itself), always go to network
  // first and never silently serve a stale cached HTML shell.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/index.html'))
    );
    return;
  }

  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response && response.status === 200 && request.url.startsWith(self.location.origin)) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request))
  );
});

// ── PUSH: show a system notification when a push message arrives ──
// Runs even when the app is closed — this is the whole point of push vs.
// the in-app notification bell, which only updates while a tab is open.
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    // Payload wasn't valid JSON — fall back to plain text rather than
    // silently dropping the notification.
    data = { title: 'AgroLink', body: event.data ? event.data.text() : '' };
  }

  const title = data.title || 'AgroLink';
  const options = {
    body: data.body || 'You have a new notification.',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    data: { url: data.url || '/' }, // read back in notificationclick below
    tag: data.tag || undefined // same tag replaces a prior notification instead of stacking duplicates
  };

  // waitUntil keeps the service worker alive until the notification is
  // actually shown. Browsers penalize (and can eventually mute) sites that
  // receive a push but don't show a visible notification for it, so this
  // always shows something — even a generic fallback — rather than ever
  // silently doing nothing.
  event.waitUntil(self.registration.showNotification(title, options));
});

// ── NOTIFICATION CLICK: focus an already-open AgroLink tab if one exists,
// otherwise open a new one ──
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.startsWith(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});
