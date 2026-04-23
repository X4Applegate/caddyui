🎉 Shipped CaddyUI v2.5.0 today!

If you're new here — CaddyUI is the open-source project I've been building. It's a web dashboard for Caddy (a modern web server), so you can manage your domains, SSL certificates, redirects, and reverse proxies through a clean UI instead of editing config files by hand. Self-hosted, free, Docker-ready.

What's new in this release:

🔐 Switchable CAPTCHA — pick Cloudflare Turnstile OR Google reCAPTCHA v3 to stop bots from hammering your login page. Plus a kill-switch env var for the inevitable "Cloudflare is down and I'm locked out of my own admin" moment.

🕒 Timezone picker — every timestamp in the UI now matches the zone you actually live in, not UTC.

🎨 Branded error pages — 404s and 502s look clean now, with a correlation ID so you can find the request in your logs instead of just staring at a blank page.

🌙 Dark-mode polish on the proxy-hosts table.

Multi-arch Docker images for amd64 + arm64, so it runs on your Raspberry Pi too. 🥧

👉 Grab it: https://github.com/X4Applegate/caddyui
🐳 `docker pull applegater/caddyui:latest`

I'm calling v2.5.0 a natural stopping point for now — but if you run into any bugs, or there's a feature you'd love to see, or something you think could work better, please let me know! Drop an issue on GitHub or message me directly. I'm happy to keep building whenever real users ask for things. 💬

Huge thanks to everyone who's been following along, reporting bugs, and suggesting features. Keeps me motivated to keep shipping. 🙏

#selfhosted #opensource #caddy #docker #homelab
