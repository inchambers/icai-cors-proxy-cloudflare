#!/bin/bash

##############################################
# InChambers Cloudflare Worker Deployment
# Automated secret management + deployment
#
# Supports both interactive (terminal) and
# non-interactive (env vars) modes.
#
# Environment variables (non-interactive):
#   OPENROUTER_API_KEY - Required
#   ORG_ID             - Optional
#   ALERT_WEBHOOK_URL  - Optional
##############################################

set -e

echo "🚀 InChambers Cloudflare Worker Deployment"
echo "==========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Detect if running in an interactive terminal
IS_INTERACTIVE=false
if [ -t 0 ]; then
  IS_INTERACTIVE=true
fi

# Check prerequisites
check_prereq() {
  if ! command -v wrangler &> /dev/null; then
    echo -e "${RED}❌ Wrangler CLI not found${NC}"
    echo "Install: npm install -g wrangler"
    exit 1
  fi

  if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ curl not found${NC}"
    exit 1
  fi

  echo -e "${GREEN}✓ Prerequisites met${NC}"
}

# Fetch JWT public key from InChambers
fetch_public_key() {
  echo ""
  echo "📥 Fetching JWT public key from InChambers..."

  JWKS_URL="https://app.inchambers.ai/.well-known/jwks.json"
  JWKS_RESPONSE=$(curl -s "$JWKS_URL")

  if [ -z "$JWKS_RESPONSE" ]; then
    echo -e "${YELLOW}⚠️  Could not fetch JWKS. Worker will fetch at runtime.${NC}"
    return 1
  fi

  PUBLIC_KEY_N=$(echo "$JWKS_RESPONSE" | grep -o '"n":"[^"]*"' | head -1 | cut -d'"' -f4)

  if [ -z "$PUBLIC_KEY_N" ]; then
    echo -e "${YELLOW}⚠️  Could not parse public key. Skipping fallback.${NC}"
    return 1
  fi

  cat > /tmp/ic_public_key.pem <<EOF
-----BEGIN PUBLIC KEY-----
$PUBLIC_KEY_N
-----END PUBLIC KEY-----
EOF

  echo -e "${GREEN}✓ Public key fetched${NC}"
  return 0
}

# Get OpenRouter API key (env var or interactive)
get_openrouter_key() {
  echo ""
  echo "🔑 OpenRouter API Key"

  # Check environment variable first
  if [ -n "$OPENROUTER_API_KEY" ]; then
    echo -e "${GREEN}✓ OpenRouter API key found in environment${NC}"
    echo "$OPENROUTER_API_KEY"
    return 0
  fi

  # Non-interactive mode: fail if no env var
  if [ "$IS_INTERACTIVE" = false ]; then
    echo -e "${RED}❌ OPENROUTER_API_KEY environment variable is required in non-interactive mode${NC}"
    echo -e "${YELLOW}Set it in your Cloudflare Pages environment variables or export it before running.${NC}"
    exit 1
  fi

  # Interactive fallback
  echo "Enter your OpenRouter API key (from https://openrouter.ai/keys):"
  read -r OPENROUTER_KEY

  if [ -z "$OPENROUTER_KEY" ]; then
    echo -e "${RED}❌ OpenRouter API key is required${NC}"
    exit 1
  fi

  echo "$OPENROUTER_KEY"
}

# Fetch organization config
fetch_org_config() {
  echo ""
  echo "🏢 Organization Configuration"

  # Check environment variable first
  if [ -n "$ORG_ID" ]; then
    echo -e "${GREEN}✓ Organization ID provided: $ORG_ID${NC}"
    echo "$ORG_ID"
    return 0
  fi

  # Non-interactive mode: skip (optional)
  if [ "$IS_INTERACTIVE" = false ]; then
    echo -e "${YELLOW}⚠️  No ORG_ID set. Skipping (optional).${NC}"
    echo ""
    return 0
  fi

  echo "Enter your InChambers access token (from browser localStorage 'ic_access_token'):"
  echo -e "${YELLOW}(Press Enter to skip and enter org ID manually)${NC}"
  read -r IC_TOKEN

  if [ -z "$IC_TOKEN" ]; then
    echo "Enter your Organization ID (from InChambers Admin Dashboard):"
    echo -e "${YELLOW}(Press Enter to skip if this worker serves multiple orgs)${NC}"
    read -r MANUAL_ORG_ID
    echo "$MANUAL_ORG_ID"
    return 0
  fi

  echo "Fetching organization details from InChambers..."
  ORG_RESPONSE=$(curl -s -H "Authorization: Bearer $IC_TOKEN" \
    "https://app.inchambers.ai/api/user/organization")

  if [ $? -ne 0 ] || [ -z "$ORG_RESPONSE" ]; then
    echo -e "${YELLOW}⚠️  Could not fetch organization. Enter manually:${NC}"
    read -r MANUAL_ORG_ID
    echo "$MANUAL_ORG_ID"
    return 0
  fi

  if command -v jq &> /dev/null; then
    FETCHED_ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.organization.id // empty')
    if [ -n "$FETCHED_ORG_ID" ]; then
      echo -e "${GREEN}✓ Organization ID fetched: $FETCHED_ORG_ID${NC}"
      echo "$FETCHED_ORG_ID"
      return 0
    fi
  fi

  echo -e "${YELLOW}⚠️  Could not parse response. Enter manually:${NC}"
  read -r MANUAL_ORG_ID
  echo "$MANUAL_ORG_ID"
}

# Get alert webhook URL (optional)
get_webhook_url() {
  echo ""
  echo "🔔 Security Alert Webhook (Optional)"

  # Check environment variable first
  if [ -n "$ALERT_WEBHOOK_URL" ]; then
    echo -e "${GREEN}✓ Alert webhook URL found in environment${NC}"
    echo "$ALERT_WEBHOOK_URL"
    return 0
  fi

  # Non-interactive mode: skip (optional)
  if [ "$IS_INTERACTIVE" = false ]; then
    echo -e "${YELLOW}⚠️  No ALERT_WEBHOOK_URL set. Skipping (optional).${NC}"
    echo ""
    return 0
  fi

  echo "Enter webhook URL for security alerts (Slack, Discord, etc.):"
  echo -e "${YELLOW}(Press Enter to skip)${NC}"
  read -r WEBHOOK_URL

  echo "$WEBHOOK_URL"
}

# Set secrets via wrangler
set_secrets() {
  local OPENROUTER_KEY=$1
  local ORG_ID=$2
  local WEBHOOK_URL=$3
  local ENV=${4:-production}

  echo ""
  echo "🔐 Setting Cloudflare Worker secrets..."

  echo "$OPENROUTER_KEY" | wrangler secret put OPENROUTER_API_KEY --env "$ENV" > /dev/null 2>&1
  echo -e "${GREEN}✓ OPENROUTER_API_KEY set${NC}"

  if [ -n "$ORG_ID" ]; then
    echo "$ORG_ID" | wrangler secret put ORGANIZATION_ID --env "$ENV" > /dev/null 2>&1
    echo -e "${GREEN}✓ ORGANIZATION_ID set${NC}"
  fi

  if [ -n "$WEBHOOK_URL" ]; then
    echo "$WEBHOOK_URL" | wrangler secret put ALERT_WEBHOOK_URL --env "$ENV" > /dev/null 2>&1
    echo -e "${GREEN}✓ ALERT_WEBHOOK_URL set${NC}"
  fi

  if [ -f /tmp/ic_public_key.pem ]; then
    cat /tmp/ic_public_key.pem | wrangler secret put JWT_PUBLIC_KEY_FALLBACK --env "$ENV" > /dev/null 2>&1
    echo -e "${GREEN}✓ JWT_PUBLIC_KEY_FALLBACK set${NC}"
    rm -f /tmp/ic_public_key.pem
  fi
}

# Deploy to Cloudflare
deploy_worker() {
  local ENV=${1:-production}

  echo ""
  echo "🚢 Deploying to Cloudflare Workers ($ENV)..."

  wrangler deploy --env "$ENV"

  echo ""
  echo -e "${GREEN}✅ Deployment complete!${NC}"
}

# Main execution
main() {
  check_prereq

  ENV=${1:-production}

  echo ""
  echo "Deploying to: $ENV"
  if [ "$IS_INTERACTIVE" = false ]; then
    echo "(Non-interactive mode — reading from environment variables)"
  fi
  echo ""

  # Fetch public key (optional, non-blocking)
  fetch_public_key || true

  # Get configuration
  OPENROUTER_KEY=$(get_openrouter_key)
  ORG_ID=$(fetch_org_config)
  WEBHOOK_URL=$(get_webhook_url)

  # Set secrets
  set_secrets "$OPENROUTER_KEY" "$ORG_ID" "$WEBHOOK_URL" "$ENV"

  # Deploy
  deploy_worker "$ENV"

  echo ""
  echo "📋 Next Steps:"
  echo "1. Copy your worker URL from the output above"
  echo "2. Go to InChambers Org Admin Dashboard → AI Platform"
  echo "3. Paste the URL and click 'Validate'"
  echo ""
  echo "🔍 Monitor logs:"
  echo "   wrangler tail --env $ENV"
  echo ""
  echo "🔐 Update secrets later:"
  echo "   wrangler secret put <SECRET_NAME> --env $ENV"
  echo ""
}

main "$@"
