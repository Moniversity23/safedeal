const CACHE_NAME = "safedeal-v2";
const STATIC_ASSETS = [
  "/",
  "/style.css",
  "/manifest.json",
  "/images/safedeallogo.png",
  "/offline.html"
];

// ✅ Install: Cache static files and offline fallback
self.addEventListener("install", (event) => {
  console.log("🧩 Installing Service Worker...");
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("📦 Caching static assets");
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// ✅ Activate: Clean old caches
self.addEventListener("activate", (event) => {
  console.log("⚙️ Activating Service Worker...");
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// ✅ Fetch: Serve cached files, then network, with offline fallback
self.addEventListener("fetch", (event) => {
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Cache new responses dynamically
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() =>
        caches.match(event.request).then(
          (res) => res || caches.match("/offline.html")
        )
      )
  );
});
