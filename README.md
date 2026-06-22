---
title: Aerolink Proxy
emoji: 🚀
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---

# Aerolink Proxy

Round-robin multi-key proxy for Claude Code. Node.js for TLS fingerprint compatibility.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_PASSWORD` | Yes | Admin dashboard password |
| `UPSTREAM_BASE_URL` | No | Default: `https://capi.aerolink.lat` |
| `MAX_RETRIES` | No | Default: `5` |

## Claude Code Config

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://your-space.hf.space/proxy",
    "ANTHROPIC_API_KEY": "<proxy-key-from-dashboard>"
  }
}
```
