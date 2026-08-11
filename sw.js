// GPREC portal service worker. Deliberately does not precache or intercept normal page/asset
// requests - this site cache-busts script.js/styles.css via a "?v=" query string on every deploy
// (see the <script>/<link> tags across every HTML page), and a caching service worker would
// undermine that by serving a stale bundle. The only real job here is Web Push: showing a
// notification when one arrives, and focusing/opening the right page when it's clicked.
self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// A pass-through fetch handler is kept (rather than omitted) only because some browsers still use
// "has a fetch handler" as an installability signal - it deliberately does no caching.
self.addEventListener("fetch", (event) => {
  event.respondWith(fetch(event.request));
});

self.addEventListener("push", (event) => {
  let data = { title: "GPREC Portal", body: "You have a new notification.", link: "/" };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch {
    // Non-JSON payload - fall back to the defaults above.
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
      data: { link: data.link || "/" },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const link = event.notification.data?.link || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url.includes(link) && "focus" in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(link);
    })
  );
});
