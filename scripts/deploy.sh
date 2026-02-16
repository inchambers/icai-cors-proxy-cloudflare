#!/bin/bash

##############################################
# InChambers Cloudflare Worker Deployment
# Automated secret management + deployment
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

  # Fetch JWKS from production
  JWKS_URL="https://app.inchambers.ai/.well-known/jwks.json"
  JWKS_RESPONSE=$(curl -s "$JWKS_URL")

  if [ -z "$JWKS_RESPONSE" ]; then
    echo -e "${YELLOW}⚠️  Could not fetch JWKS. Worker will fetch at runtime.${NC}"
    return 1
  fi

  # Extract the public key modulus (n) from first key
  # This is a simplified extraction - in production you'd parse JSON properly
  PUBLIC_KEY_N=$(echo "$JWKS_RESPONSE" | grep -o '"n":"[^"]*"' | head -1 | cut -d'"' -f4)

  if [ -z "$PUBLIC_KEY_N" ]; then
    echo -e "${YELLOW}⚠️  Could not parse public key. Skipping fallback.${NC}"
    return 1
  fi

  # Convert JWK to PEM format (simplified - assumes RSA)
  # In production, this should use a proper JWK-to-PEM converter
  cat > /tmp/ic_public_key.pem <<EOF
-----BEGIN PUBLIC KEY-----
$PUBLIC_KEY_N
-----END PUBLIC KEY-----
EOF

  echo -e "${GREEN}✓ Public key fetched${NC}"
  return 0
}

# Fetch organization config from InChambers API
fetch_org_config() {
  echo ""
  echo "🏢 Organization Configuration"

  # Check if ORG_ID already provided via environment variable
  if [ -n "$ORG_ID" ]; then
    echo -e "${GREEN}✓ Organization ID provided: $ORG_ID${NC}"
    echo "$ORG_ID"
    return 0
  fi

  echo "Enter your InChambers access token (from browser localStorage 'ic_access_token'):"
  echo -e "${YELLOW}(Press Enter to skip and enter org ID manually)${NC}"
  read -r IC_TOKEN

  if [ -z "$IC_TOKEN" ]; then
    # Manual org ID entry
    echo "Enter your Organization ID (from InChambers Admin Dashboard):"
    echo -e "${YELLOW}(Press Enter to skip if this worker serves multiple orgs)${NC}"
    read -r MANUAL_ORG_ID
    echo "$MANUAL_ORG_ID"
    return 0
  fi

  # Fetch org config from API
  echo "Fetching organization details from InChambers..."
  ORG_RESPONSE=$(curl -s -H "Authorization: Bearer $IC_TOKEN" \
    "https://app.inchambers.ai/api/user/organization")

  if [ $? -ne 0 ] || [ -z "$ORG_RESPONSE" ]; then
    echo -e "${YELLOW}⚠️  Could not fetch organization. Enter manually:${NC}"
    read -r MANUAL_ORG_ID
    echo "$MANUAL_ORG_ID"
    return 0
  fi

  # Extract org_id from JSON response (requires jq, falls back to manual if not available)
  if command -v jq &> /dev/null; then
    FETCHED_ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.organization.id // empty')
    if [ -n "$FETCHED_ORG_ID" ]; then
      echo -e "${GREEN}✓ Organization ID fetched: $FETCHED_ORG_ID${NC}"
      echo "$FETCHED_ORG_ID"
      return 0
    fi
  fi

  # Fallback: manual entry
  echo -e "${YELLOW}⚠️  Could not parse response. Enter manually:${NC}"
  read -r MANUAL_ORG_ID
  echo "$MANUAL_ORG_ID"
}

# Get OpenRouter API key
get_openrouter_key() {
  echo ""
  echo "🔑 OpenRouter API Key"
  echo "Enter your OpenRouter API key (from https://openrouter.ai/keys):"
  read -r OPENROUTER_KEY

  if [ -z "$OPENROUTER_KEY" ]; then
    echo -e "${RED}❌ OpenRouter API key is required${NC}"
    exit 1
  fi

  echo "$OPENROUTER_KEY"
}

# Get alert webhook URL (optional)
get_webhook_url() {
  echo ""
  echo "🔔 Security Alert Webhook (Optional)"
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

  # Required: OpenRouter API key
  echo "$OPENROUTER_KEY" | wrangler secret put OPENROUTER_API_KEY --env "$ENV" > /dev/null 2>&1
  echo -e "${GREEN}✓ OPENROUTER_API_KEY set${NC}"

  # Optional: Organization ID
  if [ -n "$ORG_ID" ]; then
    echo "$ORG_ID" | wrangler secret put ORGANIZATION_ID --env "$ENV" > /dev/null 2>&1
    echo -e "${GREEN}✓ ORGANIZATION_ID set${NC}"
  fi

  # Optional: Alert webhook
  if [ -n "$WEBHOOK_URL" ]; then
    echo "$WEBHOOK_URL" | wrangler secret put ALERT_WEBHOOK_URL --env "$ENV" > /dev/null 2>&1
    echo -e "${GREEN}✓ ALERT_WEBHOOK_URL set${NC}"
  fi

  # Optional: JWT fallback key
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

  # Determine environment
  ENV=${1:-production}

  echo ""
  echo "Deploying to: $ENV"
  echo ""

  # Fetch public key (optional, non-blocking)
  fetch_public_key || true

  # Get user inputs
  OPENROUTER_KEY=$(get_openrouter_key)
  ORG_ID=$(fetch_org_config)
  WEBHOOK_URL=$(get_webhook_url)

  # Set secrets
  set_secrets "$OPENROUTER_KEY" "$ORG_ID" "$WEBHOOK_URL" "$ENV"

  # Deploy
  deploy_worker "$ENV"

  # Show post-deployment instructions
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

# Run main with environment argument
main "$@"
