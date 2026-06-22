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

Round-robin multi-key proxy for Claude Code upstream providers.

## Features

- Round-robin key rotation across multiple API keys
- Automatic retry on 402/auth/5xx errors with next key
- Raw passthrough - no request modification (preserves Claude Code fingerprint)
- SSE streaming support
- Web dashboard for key management
- Password-protected admin panel

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_PASSWORD` | Yes | - | Password for admin dashboard |
| `UPSTREAM_BASE_URL` | No | `https://capi.aerolink.lat` | Upstream provider URL |
| `PROXY_KEY` | Auto | (generated) | Auth key for Claude Code requests |
| `MAX_RETRIES` | No | `5` | Max key rotation attempts |
| `PORT` | No | `7860` | Server port |

## Setup

1. Deploy to Hugging Face Spaces (Docker)
2. Set `ADMIN_PASSWORD` in Space secrets
3. Open `/admin` to access the dashboard
4. Add your API keys in the dashboard
5. Copy the proxy key and configure Claude Code

## Claude Code Configuration

Add to your Claude Code settings:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://your-space.hf.space/proxy",
    "ANTHROPIC_API_KEY": "<proxy-key-from-dashboard>"
  }
}
```
