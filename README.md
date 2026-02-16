# InChambers CORS Proxy - Cloudflare Worker

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/inchambers/icai-cors-proxy-cloudflare)

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

#### Option 1: Automated Deployment (Recommended)

**From InChambers Admin Dashboard:**
1. Go to Organization Admin Dashboard → AI Platform → Configure
2. Select "Cloudflare Worker"
3. Copy the pre-configured command (includes your ORG_ID)
4. Run it in your terminal

**Manual Command:**
```bash
# Clone and setup
git clone https://github.com/inchambers/icai-cors-proxy-cloudflare.git
cd icai-cors-proxy-cloudflare
npm install

# Login to Cloudflare
wrangler login

# Deploy with your organization ID (auto-configures everything)
ORG_ID=<your-org-id> npm run deploy
```

The script will:
1. ✅ Use your ORG_ID from environment variable (or prompt if not set)
2. ✅ Fetch JWT public key from InChambers automatically
3. ✅ Prompt for your OpenRouter API key
4. ✅ Prompt for alert webhook URL (optional)
5. ✅ Set all secrets automatically
6. ✅ Deploy to Cloudflare Workers

#### Option 2: Manual Deployment

```bash
# Install dependencies
npm install

# Login to Cloudflare
wrangler login

# Set secrets manually
npm run secret:openrouter     # Required: OpenRouter API key
npm run secret:org            # Optional: Organization ID
npm run secret:webhook        # Optional: Alert webhook URL
npm run secret:jwt-fallback   # Optional: JWT fallback key

# Deploy
npm run deploy:manual
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

| Variable | Required | Description | Auto-Set by Script? |
|----------|----------|-------------|---------------------|
| `OPENROUTER_API_KEY` | **Yes** | Your OpenRouter API key | ✅ Yes (prompts) |
| `ORGANIZATION_ID` | No | Organization UUID for access control | ✅ Yes (prompts) |
| `ALERT_WEBHOOK_URL` | No | Webhook URL for security alerts | ✅ Yes (prompts) |
| `JWT_PUBLIC_KEY_FALLBACK` | No | RS256 public key for JWT verification | ✅ Yes (auto-fetched) |
| `AUDIT_LOG` | No | Set to "false" to disable audit logging | ❌ Manual (wrangler.toml) |

### Setting Secrets Manually

If you prefer manual control:

```bash
# Required: OpenRouter API key
npm run secret:openrouter

# Optional: Organization ID (prevents cross-org access)
npm run secret:org

# Optional: Alert webhook URL (Slack, Discord, etc.)
npm run secret:webhook

# Optional: JWT fallback key (for cold-start resilience)
npm run secret:jwt-fallback
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` or `/api/health` | GET | Health check endpoint |
| `/chat/completions`<br/>`/api/chat/completions`<br/>`/v1/chat/completions` | POST | OpenRouter proxy with JWT auth |

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
