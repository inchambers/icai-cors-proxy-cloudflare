# InChambers CORS Proxy - Cloudflare Worker

A lightweight, edge-deployed CORS proxy for OpenRouter with true streaming support.

## Features

- **True Streaming**: No buffering - SSE events arrive immediately
- **Zero Cold Starts**: V8 isolates boot in milliseconds
- **Global Edge**: Deployed to 300+ Cloudflare PoPs worldwide
- **JWT Verification**: RS256 verification via JWKS from InChambers
- **Audit Logging**: Optional structured JSON logs for compliance

## Quick Start

### Prerequisites

1. [Cloudflare Account](https://dash.cloudflare.com/sign-up)
2. [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
3. [OpenRouter API Key](https://openrouter.ai/keys)

### Installation

```bash
# Install dependencies
npm install

# Login to Cloudflare
wrangler login

# Set your OpenRouter API key
npm run secret:openrouter
# (paste your key when prompted)

# Optional: Set registration token from InChambers dashboard
npm run secret:registration

# Deploy to Cloudflare
npm run deploy
```

### Get Your Worker URL

After deployment, Wrangler will output your worker URL:
```
Published icai-cors-proxy (1.23 sec)
  https://icai-cors-proxy.<your-subdomain>.workers.dev
```

Copy this URL and paste it into your InChambers Organization Admin Dashboard.

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENROUTER_API_KEY` | Yes | Your OpenRouter API key |
| `REGISTRATION_TOKEN` | No | Token for auto-registration (from IC dashboard) |
| `JWT_PUBLIC_KEY_FALLBACK` | No | RS256 public key for cold-start resilience |
| `AUDIT_LOG` | No | Set to "false" to disable audit logging |

### Setting Secrets

```bash
# Required: OpenRouter API key
wrangler secret put OPENROUTER_API_KEY

# Optional: Registration token
wrangler secret put REGISTRATION_TOKEN

# Optional: JWT fallback key
wrangler secret put JWT_PUBLIC_KEY_FALLBACK
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (also `/api/health`) |
| `/api/chat/completions` | POST | OpenRouter proxy (also `/chat/completions`, `/v1/chat/completions`) |
| `/api/register-callback` | POST | Auto-registration callback |

## Development

```bash
# Start local dev server
npm run dev

# View live logs
npm run tail
```

## Comparison: Cloudflare Worker vs Azure Function

| Feature | Cloudflare Worker | Azure Function |
|---------|------------------|----------------|
| Cold Starts | None (V8 isolates) | 2-10 seconds |
| Streaming | True (no buffering) | Buffered (consumption plan) |
| Edge Locations | 300+ global PoPs | Single region |
| Pricing | $0.50/M requests (first 10M free) | ~$0.20/M requests |
| Setup | Single `wrangler deploy` | ARM templates + Function App |
| JWT Verification | WebCrypto (native) | Node.js (jsonwebtoken) |

## Troubleshooting

### "JWKS fetch failed"

The worker fetches JWKS from `https://inchambers.ai/.well-known/jwks.json`. If this fails:
1. Set `JWT_PUBLIC_KEY_FALLBACK` secret with the RS256 public key
2. Check Cloudflare dashboard for blocked requests

### "Invalid or expired token"

1. Ensure you're logged into InChambers
2. Check that your subscription is active
3. Try logging out and back in

### Streaming not working

1. Verify your client supports SSE
2. Check browser DevTools Network tab for chunked responses
3. Ensure no proxy/CDN is buffering the response

## Support

For issues with this proxy, contact your organization admin or InChambers support.
