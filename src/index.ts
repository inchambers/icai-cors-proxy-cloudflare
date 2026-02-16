/**
 * InChambers CORS Proxy - Cloudflare Worker
 *
 * A lightweight, edge-deployed CORS proxy for OpenRouter with:
 * - True streaming support (no buffering)
 * - JWT verification via JWKS with replay protection
 * - Zero cold starts (V8 isolates)
 * - Global edge deployment (300+ PoPs)
 * - Rate limiting (60 req/min per user)
 * - Organization-level access control
 * - Abuse detection and alerting
 *
 * Environment Variables (secrets):
 * - OPENROUTER_API_KEY: Your OpenRouter API key (required)
 * - JWT_PUBLIC_KEY_FALLBACK: (optional) RS256 public key for cold-start resilience
 * - ORGANIZATION_ID: (optional) Organization UUID for cross-org access prevention
 * - ALERT_WEBHOOK_URL: (optional) Webhook URL for security alerts
 * - AUDIT_LOG: "true" to enable audit logging (default: true)
 *
 * Security Features:
 * - JWT replay protection via JTI tracking
 * - Per-user rate limiting (60 requests per 60 seconds)
 * - Organization ID verification (prevents cross-org access)
 * - Request size limits (5MB body, 200K input tokens, 32K output tokens)
 * - Abuse pattern detection (high-cost requests, large prompts, rapid requests)
 * - JWKS cache TTL reduced to 15 minutes (enhanced security)
 */

export interface Env {
  OPENROUTER_API_KEY: string;
  JWT_PUBLIC_KEY_FALLBACK?: string;
  AUDIT_LOG?: string;
  ORGANIZATION_ID?: string; // For org-level authorization
  ALERT_WEBHOOK_URL?: string; // For security alerts
}

// JWKS cache (reduced TTL for security)
let jwksCache: { keys: JsonWebKey[]; fetchedAt: number } | null = null;
const JWKS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes (was 1 hour)
const JWKS_URL = 'https://inchambers.ai/.well-known/jwks.json';

// JWT replay protection: Track used JTIs to prevent replay attacks
const usedJTIs = new Map<string, number>(); // jti -> expiration timestamp
const JTI_CLEANUP_INTERVAL = 1000; // Cleanup every 1000 requests
let jtiCleanupCounter = 0;

// Rate limiting: Track requests per user
interface RateLimitEntry {
  count: number;
  resetAt: number;
}
const rateLimits = new Map<string, RateLimitEntry>();
const RATE_LIMIT_REQUESTS = 60; // 60 requests
const RATE_LIMIT_WINDOW = 60 * 1000; // per 60 seconds

// Abuse detection: Track suspicious patterns
interface AbuseMetrics {
  highCostRequests: number; // Requests with max_tokens > 16K
  largePrompts: number; // Prompts > 50K tokens
  rapidRequests: number; // > 30 req/min
}
const abuseMetrics = new Map<string, AbuseMetrics>();


// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://app.inchambers.ai',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
];

// OpenRouter API base URL
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';

/**
 * Fetch and cache JWKS from InChambers
 */
async function getJwks(env: Env): Promise<JsonWebKey[]> {
  // PERFORMANCE: Use fallback key by default if available (skip JWKS fetch)
  if (env.JWT_PUBLIC_KEY_FALLBACK) {
    return [{
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n: extractModulusFromPEM(env.JWT_PUBLIC_KEY_FALLBACK),
      e: 'AQAB',
      kid: '67558b1f4805e985', // Must match backend JWT kid
    }];
  }

  const now = Date.now();

  // Return cached JWKS if still valid
  if (jwksCache && now - jwksCache.fetchedAt < JWKS_CACHE_TTL) {
    return jwksCache.keys;
  }

  try {
    const response = await fetch(JWKS_URL, {
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`JWKS fetch failed: ${response.status}`);
    }

    const jwks = await response.json() as { keys: JsonWebKey[] };
    jwksCache = { keys: jwks.keys, fetchedAt: now };
    return jwks.keys;
  } catch (error) {
    // If we have stale cache, use it
    if (jwksCache) {
      console.warn('JWKS fetch failed, using stale cache');
      return jwksCache.keys;
    }

    throw error;
  }
}

/**
 * Extract modulus from PEM-encoded public key
 */
function extractModulusFromPEM(pem: string): string {
  // Remove PEM headers and newlines
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  return base64;
}

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): Uint8Array {
  // Add padding
  const padding = '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = (str + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

/**
 * Verify JWT and extract user ID
 */
async function verifyJwt(token: string, env: Env): Promise<{ userId: string; email?: string; orgId?: string } | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
    if (header.alg !== 'RS256') {
      console.error('Unsupported algorithm:', header.alg);
      return null;
    }

    // Get JWKS and find matching key
    const keys = await getJwks(env);
    let key: JsonWebKey | undefined;

    if (header.kid) {
      key = keys.find(k => k.kid === header.kid);
    }
    if (!key && keys.length > 0) {
      key = keys[0]; // Use first key if no kid match
    }

    if (!key) {
      console.error('No matching JWK found');
      return null;
    }

    // Import the public key
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      key,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Verify signature
    const signatureData = base64UrlDecode(signatureB64);
    const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

    const valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      signatureData,
      signedData
    );

    if (!valid) {
      console.error('JWT signature verification failed');
      return null;
    }

    // Decode payload
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      console.error('JWT expired');
      return null;
    }

    // Check for JTI replay attack
    if (payload.jti) {
      // Check if JTI has been used before
      if (usedJTIs.has(payload.jti)) {
        console.error('JWT replay attack detected - JTI already used:', payload.jti);
        return null;
      }

      // Mark JTI as used with expiration timestamp
      usedJTIs.set(payload.jti, payload.exp * 1000);

      // Cleanup expired JTIs periodically
      jtiCleanupCounter++;
      if (jtiCleanupCounter >= JTI_CLEANUP_INTERVAL) {
        const now = Date.now();
        for (const [jti, exp] of usedJTIs.entries()) {
          if (exp < now) {
            usedJTIs.delete(jti);
          }
        }
        jtiCleanupCounter = 0;
      }
    }

    return {
      userId: payload.sub,
      email: payload.email,
      orgId: payload.org_id,
    };
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

/**
 * Set CORS headers
 */
function setCorsHeaders(response: Response, origin: string | null): Response {
  const headers = new Headers(response.headers);

  // Check if origin is allowed
  const allowedOrigin = origin && ALLOWED_ORIGINS.some(allowed => {
    if (allowed.includes('localhost')) {
      return origin.includes('localhost');
    }
    return origin === allowed;
  }) ? origin : ALLOWED_ORIGINS[0];

  headers.set('Access-Control-Allow-Origin', allowedOrigin);
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID');
  headers.set('Access-Control-Expose-Headers', 'X-Request-ID');
  headers.set('Access-Control-Max-Age', '86400');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Handle OPTIONS preflight requests
 */
function handleOptions(request: Request): Response {
  const origin = request.headers.get('Origin');
  return setCorsHeaders(new Response(null, { status: 204 }), origin);
}

/**
 * Handle health check
 */
async function handleHealth(env: Env, request: Request): Promise<Response> {
  const origin = request.headers.get('Origin');

  const response = new Response(JSON.stringify({
    status: 'ok',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    region: (request.cf as any)?.colo || 'unknown',
    provider: 'openrouter',
    providerConfigured: !!env.OPENROUTER_API_KEY,
    rateLimitRpm: 1000,
    monthlyQuota: 0,
    monthlyUsed: 0,
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  return setCorsHeaders(response, origin);
}

/**
 * Handle chat completions - main proxy logic
 */
async function handleChatCompletions(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get('Origin');
  const startTime = Date.now();

  // Extract and verify JWT
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return setCorsHeaders(new Response(JSON.stringify({ error: 'Missing authorization token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }

  const token = authHeader.substring(7);
  const user = await verifyJwt(token, env);

  if (!user) {
    return setCorsHeaders(new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }

  // Rate limiting check
  const now = Date.now();
  const userRateLimit = rateLimits.get(user.userId);

  if (userRateLimit) {
    if (now < userRateLimit.resetAt) {
      if (userRateLimit.count >= RATE_LIMIT_REQUESTS) {
        return setCorsHeaders(new Response(JSON.stringify({
          error: 'Rate limit exceeded',
          details: `Maximum ${RATE_LIMIT_REQUESTS} requests per ${RATE_LIMIT_WINDOW / 1000} seconds`,
          retryAfter: Math.ceil((userRateLimit.resetAt - now) / 1000),
        }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(Math.ceil((userRateLimit.resetAt - now) / 1000)),
          },
        }), origin);
      }
      userRateLimit.count++;
    } else {
      // Reset window
      rateLimits.set(user.userId, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    }
  } else {
    // First request from this user
    rateLimits.set(user.userId, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
  }

  // Organization verification (if ORGANIZATION_ID is set)
  if (env.ORGANIZATION_ID && user.orgId !== env.ORGANIZATION_ID) {
    // Send alert webhook for cross-org access attempt
    if (env.ALERT_WEBHOOK_URL) {
      fetch(env.ALERT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert: 'cross_org_access_attempt',
          userId: user.userId,
          userOrgId: user.orgId,
          expectedOrgId: env.ORGANIZATION_ID,
          timestamp: new Date().toISOString(),
        }),
      }).catch(() => {}); // Fire and forget
    }

    return setCorsHeaders(new Response(JSON.stringify({
      error: 'Access denied',
      details: 'Organization mismatch',
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }

  // Check OpenRouter API key
  if (!env.OPENROUTER_API_KEY) {
    return setCorsHeaders(new Response(JSON.stringify({ error: 'OpenRouter API key not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }

  try {
    // Check request body size (5MB limit for legal contracts)
    const contentLength = request.headers.get('Content-Length');
    const MAX_BODY_SIZE = 5 * 1024 * 1024; // 5MB
    if (contentLength && parseInt(contentLength) > MAX_BODY_SIZE) {
      return setCorsHeaders(new Response(JSON.stringify({
        error: 'Request body too large',
        details: `Maximum ${MAX_BODY_SIZE / (1024 * 1024)}MB allowed`,
      }), {
        status: 413,
        headers: { 'Content-Type': 'application/json' },
      }), origin);
    }

    // Parse request body
    const body = await request.json() as {
      model: string;
      messages: any[];
      stream?: boolean;
      temperature?: number;
      max_tokens?: number;
    };

    // Token limits for legal contracts
    const MAX_INPUT_TOKENS = 200000; // ~300 pages
    const MAX_OUTPUT_TOKENS = 32000; // ~50 pages

    // Estimate input tokens (rough approximation: 1 token ≈ 4 chars)
    const inputText = body.messages.map((m: any) => m.content || '').join('');
    const estimatedInputTokens = Math.ceil(inputText.length / 4);

    if (estimatedInputTokens > MAX_INPUT_TOKENS) {
      return setCorsHeaders(new Response(JSON.stringify({
        error: 'Input too large',
        details: `Maximum ${MAX_INPUT_TOKENS} tokens (~${Math.floor(MAX_INPUT_TOKENS / 667)} pages) allowed`,
      }), {
        status: 413,
        headers: { 'Content-Type': 'application/json' },
      }), origin);
    }

    if (body.max_tokens && body.max_tokens > MAX_OUTPUT_TOKENS) {
      return setCorsHeaders(new Response(JSON.stringify({
        error: 'max_tokens too large',
        details: `Maximum ${MAX_OUTPUT_TOKENS} tokens allowed`,
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }), origin);
    }

    // Track abuse metrics
    const userAbuse = abuseMetrics.get(user.userId) || {
      highCostRequests: 0,
      largePrompts: 0,
      rapidRequests: 0
    };

    if (body.max_tokens && body.max_tokens > 16000) {
      userAbuse.highCostRequests++;
    }
    if (estimatedInputTokens > 50000) {
      userAbuse.largePrompts++;
    }

    const recentRate = rateLimits.get(user.userId);
    if (recentRate && recentRate.count > 30) {
      userAbuse.rapidRequests++;
    }

    abuseMetrics.set(user.userId, userAbuse);

    // Alert on suspicious patterns
    if (env.ALERT_WEBHOOK_URL) {
      const isAbusive = userAbuse.highCostRequests > 10 ||
                       userAbuse.largePrompts > 5 ||
                       userAbuse.rapidRequests > 3;

      if (isAbusive) {
        fetch(env.ALERT_WEBHOOK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            alert: 'abuse_pattern_detected',
            userId: user.userId,
            email: user.email,
            metrics: userAbuse,
            timestamp: new Date().toISOString(),
          }),
        }).catch(() => {}); // Fire and forget
      }
    }

    // Audit log (if enabled)
    if (env.AUDIT_LOG !== 'false') {
      console.log(JSON.stringify({
        event: 'chat_request',
        userId: user.userId,
        model: body.model,
        stream: body.stream ?? false,
        timestamp: new Date().toISOString(),
      }));
    }

    // Forward to OpenRouter
    const openRouterResponse = await fetch(`${OPENROUTER_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://app.inchambers.ai',
        'X-Title': 'InChambers Legal AI',
      },
      body: JSON.stringify(body),
    });

    // Handle streaming responses
    if (body.stream && openRouterResponse.body) {
      const { readable, writable } = new TransformStream();

      // Pipe the response through without buffering
      openRouterResponse.body.pipeTo(writable).catch(err => {
        console.error('Stream error:', err);
      });

      const response = new Response(readable, {
        status: openRouterResponse.status,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });

      // Audit log completion
      if (env.AUDIT_LOG !== 'false') {
        console.log(JSON.stringify({
          event: 'chat_response',
          userId: user.userId,
          model: body.model,
          status: openRouterResponse.status,
          latencyMs: Date.now() - startTime,
          streaming: true,
        }));
      }

      return setCorsHeaders(response, origin);
    }

    // Handle non-streaming responses
    const responseBody = await openRouterResponse.text();

    // Audit log completion
    if (env.AUDIT_LOG !== 'false') {
      console.log(JSON.stringify({
        event: 'chat_response',
        userId: user.userId,
        model: body.model,
        status: openRouterResponse.status,
        latencyMs: Date.now() - startTime,
        streaming: false,
      }));
    }

    const response = new Response(responseBody, {
      status: openRouterResponse.status,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    return setCorsHeaders(response, origin);
  } catch (error: any) {
    console.error('Proxy error:', error);

    // Audit log error
    if (env.AUDIT_LOG !== 'false') {
      console.log(JSON.stringify({
        event: 'chat_error',
        userId: user.userId,
        error: error.message,
        latencyMs: Date.now() - startTime,
      }));
    }

    return setCorsHeaders(new Response(JSON.stringify({
      error: 'Proxy error',
      details: error.message,
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }
}

/**
 * Main request handler
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle OPTIONS preflight
    if (request.method === 'OPTIONS') {
      return handleOptions(request);
    }

    // Route requests
    // Health check (try multiple paths for compatibility)
    if (path === '/health' || path === '/api/health') {
      return await handleHealth(env, request);
    }

    // Chat completions (main proxy endpoint)
    if ((path === '/chat/completions' || path === '/api/chat/completions' || path === '/v1/chat/completions') && request.method === 'POST') {
      return handleChatCompletions(request, env);
    }

    // 404 for unknown routes
    const origin = request.headers.get('Origin');
    return setCorsHeaders(new Response(JSON.stringify({
      error: 'Not found',
      path,
      availableEndpoints: ['/health', '/api/chat/completions'],
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  },
};
