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
        $token = $this->extractBearerToken($request);

        if (! $token) {
            return $this->unauthorized('Missing authorization token.');
        }

        // Validate token and get user info (cached for performance)
        $userData = $this->validateToken($token);

        if (! $userData) {
            return $this->unauthorized('Invalid or expired token.');
        }

        // Check required scopes
        if (! empty($scopes)) {
            $tokenScopes = $userData['scopes'] ?? [];

            foreach ($scopes as $requiredScope) {
                if (! in_array($requiredScope, $tokenScopes)) {
                    return $this->forbidden("Missing required scope: {$requiredScope}");
                }
            }
        }

        // Create KaizenUser and attach to request
        $user = new KaizenUser;
        $user->setRaw($userData)->map([
            'id' => $userData['id'] ?? null,
            'name' => $userData['name'] ?? null,
            'email' => $userData['email'] ?? null,
            'avatar' => $userData['avatar_url'] ?? $userData['avatar'] ?? null,
        ]);
        $user->token = $token;

        $request->merge(['kaizen_user' => $user]);
        $request->setUserResolver(fn () => $user);

        return $next($request);
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
