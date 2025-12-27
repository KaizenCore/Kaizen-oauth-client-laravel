<?php

namespace Kaizen\OAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Kaizen\OAuth\KaizenProvider;
use Kaizen\OAuth\KaizenUser;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to validate Kaizen OAuth Bearer tokens for API endpoints.
 *
 * Supports two authentication methods:
 * 1. Bearer token in Authorization header (standard API auth)
 * 2. Session-based auth fallback (for SPAs on same domain)
 *
 * Usage:
 *   Route::middleware('kaizen.api')->group(function () {
 *       Route::get('/api/user', fn() => request()->kaizenUser());
 *   });
 *
 *   // With required scopes:
 *   Route::middleware('kaizen.api:skins:read,skins:create')->get('/api/skins', ...);
 */
class ValidateKaizenToken
{
    public function __construct(
        protected KaizenProvider $provider
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  string  ...$scopes  Required scopes (comma-separated in route definition)
     */
    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        // Try Bearer token first
        $token = $this->extractBearerToken($request);

        if ($token) {
            return $this->authenticateWithToken($request, $next, $token, $scopes);
        }

        // Fallback to session-based auth (for SPAs on same domain)
        if ($this->hasSessionAuth()) {
            return $this->authenticateWithSession($request, $next, $scopes);
        }

        return $this->unauthorized('Missing authorization token.');
    }

    /**
     * Authenticate using Bearer token.
     */
    protected function authenticateWithToken(Request $request, Closure $next, string $token, array $scopes): Response
    {
        // Validate token and get user info (cached for performance)
        $userData = $this->validateToken($token);

        if (! $userData) {
            return $this->unauthorized('Invalid or expired token.');
        }

        // Create KaizenUser and attach to request
        $user = $this->createKaizenUser($userData, $token);

        $request->merge(['kaizen_user' => $user]);
        $request->setUserResolver(fn () => $user);

        // Admin bypass - admins have access to all routes
        if ($this->isAdmin($userData)) {
            return $next($request);
        }

        // Check required scopes for non-admin users
        if (! empty($scopes)) {
            $tokenScopes = $userData['scopes'] ?? [];

            foreach ($scopes as $requiredScope) {
                if (! in_array($requiredScope, $tokenScopes)) {
                    return $this->forbidden("Missing required scope: {$requiredScope}");
                }
            }
        }

        return $next($request);
    }

    /**
     * Authenticate using session (fallback for SPAs).
     */
    protected function authenticateWithSession(Request $request, Closure $next, array $scopes): Response
    {
        $sessionUser = session('kaizen_user');
        // Support both 'kaizen_access_token' and 'kaizen_token' for flexibility
        $sessionToken = session('kaizen_access_token') ?? session('kaizen_token');
        $sessionScopes = session('kaizen_scopes', []);

        if (! $sessionUser || ! $sessionToken) {
            return $this->unauthorized('Session expired. Please log in again.');
        }

        // Check if token is expired
        $expiresAt = session('kaizen_expires_at');
        if ($expiresAt && now()->greaterThan($expiresAt)) {
            // Try to refresh the token
            $refreshToken = session('kaizen_refresh_token');
            if ($refreshToken) {
                try {
                    $newTokens = $this->provider->refreshToken($refreshToken);
                    $this->storeSessionTokens($newTokens);
                    $sessionToken = $newTokens['access_token'];
                } catch (\Exception $e) {
                    $this->clearSession();

                    return $this->unauthorized('Session expired. Please log in again.');
                }
            } else {
                $this->clearSession();

                return $this->unauthorized('Session expired. Please log in again.');
            }
        }

        // Create KaizenUser from session data
        $userData = array_merge($sessionUser, ['scopes' => $sessionScopes]);
        $user = $this->createKaizenUser($userData, $sessionToken);

        $request->merge(['kaizen_user' => $user]);
        $request->setUserResolver(fn () => $user);

        // Admin bypass - admins have access to all routes
        if ($this->isAdmin($sessionUser)) {
            return $next($request);
        }

        // Check required scopes for non-admin users
        if (! empty($scopes)) {
            foreach ($scopes as $requiredScope) {
                if (! in_array($requiredScope, $sessionScopes)) {
                    return $this->forbidden("Missing required scope: {$requiredScope}");
                }
            }
        }

        return $next($request);
    }

    /**
     * Check if the user is an admin.
     *
     * Supports both "role" (string) and "roles" (array) formats.
     */
    protected function isAdmin(array $userData): bool
    {
        // Check "role" as string
        if (($userData['role'] ?? null) === 'admin') {
            return true;
        }

        // Check "roles" as array
        $roles = $userData['roles'] ?? [];

        return is_array($roles) && in_array('admin', $roles);
    }

    /**
     * Check if session-based auth is available.
     */
    protected function hasSessionAuth(): bool
    {
        $hasToken = session()->has('kaizen_access_token') || session()->has('kaizen_token');

        return $hasToken && session()->has('kaizen_user');
    }

    /**
     * Create a KaizenUser from user data.
     */
    protected function createKaizenUser(array $userData, string $token): KaizenUser
    {
        $user = new KaizenUser;
        $user->setRaw($userData)->map([
            'id' => $userData['id'] ?? null,
            'name' => $userData['name'] ?? null,
            'email' => $userData['email'] ?? null,
            'avatar' => $userData['avatar_url'] ?? $userData['avatar'] ?? null,
        ]);
        $user->token = $token;

        return $user;
    }

    /**
     * Store refreshed tokens in session.
     */
    protected function storeSessionTokens(array $tokens): void
    {
        session([
            'kaizen_access_token' => $tokens['access_token'],
            'kaizen_refresh_token' => $tokens['refresh_token'] ?? session('kaizen_refresh_token'),
            'kaizen_expires_at' => now()->addSeconds($tokens['expires_in'] ?? 3600),
        ]);
    }

    /**
     * Clear session data.
     */
    protected function clearSession(): void
    {
        session()->forget([
            'kaizen_access_token',
            'kaizen_refresh_token',
            'kaizen_expires_at',
            'kaizen_user',
            'kaizen_scopes',
        ]);
    }

    /**
     * Extract Bearer token from Authorization header.
     */
    protected function extractBearerToken(Request $request): ?string
    {
        $header = $request->header('Authorization', '');

        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        return null;
    }

    /**
     * Validate token against Kaizen OAuth server.
     *
     * @return array<string, mixed>|null
     */
    protected function validateToken(string $token): ?array
    {
        // Cache token validation to reduce API calls
        $cacheKey = 'kaizen_token:'.hash('sha256', $token);
        $cacheTtl = config('kaizen.token_cache_ttl', 300);

        return Cache::remember($cacheKey, $cacheTtl, function () use ($token) {
            return $this->provider->validateToken($token);
        });
    }

    /**
     * Return an unauthorized response.
     */
    protected function unauthorized(string $message): Response
    {
        return response()->json([
            'error' => 'unauthorized',
            'message' => $message,
        ], 401);
    }

    /**
     * Return a forbidden response.
     */
    protected function forbidden(string $message): Response
    {
        return response()->json([
            'error' => 'forbidden',
            'message' => $message,
        ], 403);
    }
}
