/**
 * InChambers CORS Proxy - Cloudflare Worker
 *
 * A lightweight, edge-deployed CORS proxy for OpenRouter with:
 * - True streaming support (no buffering)
 * - JWT verification via JWKS
 * - Zero cold starts (V8 isolates)
 * - Global edge deployment (300+ PoPs)
 *
 * Environment Variables (secrets):
 * - OPENROUTER_API_KEY: Your OpenRouter API key
 * - JWT_PUBLIC_KEY_FALLBACK: (optional) RS256 public key for cold-start resilience
 * - REGISTRATION_TOKEN: Token for auto-registration callback
 * - AUDIT_LOG: "true" to enable audit logging (default: true)
 */

export interface Env {
  OPENROUTER_API_KEY: string;
  JWT_PUBLIC_KEY_FALLBACK?: string;
  REGISTRATION_TOKEN?: string;
  AUDIT_LOG?: string;
}

// JWKS cache
let jwksCache: { keys: JsonWebKey[]; fetchedAt: number } | null = null;
const JWKS_CACHE_TTL = 60 * 60 * 1000; // 1 hour
const JWKS_URL = 'https://inchambers.ai/.well-known/jwks.json';

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
    // If fetch fails and we have fallback key, use it
    if (env.JWT_PUBLIC_KEY_FALLBACK) {
      console.warn('JWKS fetch failed, using fallback key');
      return [{
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        n: extractModulusFromPEM(env.JWT_PUBLIC_KEY_FALLBACK),
        e: 'AQAB',
      }];
    }

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
async function verifyJwt(token: string, env: Env): Promise<{ userId: string; email?: string } | null> {
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

    return {
      userId: payload.sub,
      email: payload.email,
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

  // Auto-register on first health check if registration token exists
  if (env.REGISTRATION_TOKEN) {
    try {
      const workerUrl = new URL(request.url).origin;
      await fetch(`${workerUrl}/api/register-callback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          registrationToken: env.REGISTRATION_TOKEN,
          corsProxyUrl: workerUrl,
        }),
      }).catch(() => {
        // Silent fail - registration will be retried on next health check
      });
    } catch {
      // Ignore auto-registration errors
    }
  }

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
 * Handle registration callback for auto-setup
 */
async function handleRegisterCallback(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get('Origin');

  try {
    const body = await request.json() as {
      registrationToken: string;
      corsProxyUrl: string;
    };

    // Validate registration token
    if (!env.REGISTRATION_TOKEN || body.registrationToken !== env.REGISTRATION_TOKEN) {
      return setCorsHeaders(new Response(JSON.stringify({ error: 'Invalid registration token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }), origin);
    }

    // Call back to InChambers API to complete registration
    const callbackResponse = await fetch('https://app.inchambers.ai/api/org/ai-platform/register-callback', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Registration-Token': body.registrationToken,
      },
      body: JSON.stringify({
        cors_proxy_url: body.corsProxyUrl,
        platform_type: 'cloudflare_worker',
      }),
    });

    if (!callbackResponse.ok) {
      const errorText = await callbackResponse.text();
      return setCorsHeaders(new Response(JSON.stringify({
        error: 'Registration callback failed',
        details: errorText,
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }), origin);
    }

    return setCorsHeaders(new Response(JSON.stringify({
      success: true,
      message: 'Registration completed',
    }), {
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  } catch (error: any) {
    return setCorsHeaders(new Response(JSON.stringify({
      error: 'Registration failed',
      details: error.message,
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }
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

  // Check OpenRouter API key
  if (!env.OPENROUTER_API_KEY) {
    return setCorsHeaders(new Response(JSON.stringify({ error: 'OpenRouter API key not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  }

  try {
    // Parse request body
    const body = await request.json() as {
      model: string;
      messages: any[];
      stream?: boolean;
      temperature?: number;
      max_tokens?: number;
    };

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

    // Registration callback
    if ((path === '/api/register-callback' || path === '/register-callback') && request.method === 'POST') {
      return handleRegisterCallback(request, env);
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
      availableEndpoints: ['/health', '/api/chat/completions', '/api/register-callback'],
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    }), origin);
  },
};
