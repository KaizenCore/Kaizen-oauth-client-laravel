<?php

namespace Kaizen\OAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureKaizenToken
{
    /**
     * Handle an incoming request.
     *
     * Ensures a valid Kaizen OAuth token exists in the session.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = session('kaizen_access_token');
        $expiresAt = session('kaizen_expires_at');

        if (! $token) {
            return $this->handleUnauthenticated($request);
        }

        // Check if token is expired
        if ($expiresAt && now()->greaterThan($expiresAt)) {
            $refreshToken = session('kaizen_refresh_token');

            if ($refreshToken) {
                try {
                    $newTokens = $this->refreshToken($refreshToken);
                    $this->storeTokens($newTokens);
                } catch (\Exception $e) {
                    $this->clearTokens();

                    return $this->handleUnauthenticated($request);
                }
            } else {
                $this->clearTokens();

                return $this->handleUnauthenticated($request);
            }
        }

        return $next($request);
    }

    /**
     * Refresh the access token.
     */
    protected function refreshToken(string $refreshToken): array
    {
        $provider = app(\Kaizen\OAuth\KaizenProvider::class);

        return $provider->refreshToken($refreshToken);
    }

    /**
     * Store tokens in the session.
     */
    protected function storeTokens(array $tokens): void
    {
        session([
            'kaizen_access_token' => $tokens['access_token'],
            'kaizen_refresh_token' => $tokens['refresh_token'] ?? session('kaizen_refresh_token'),
            'kaizen_expires_at' => now()->addSeconds($tokens['expires_in'] ?? 3600),
        ]);
    }

    /**
     * Clear tokens from the session.
     */
    protected function clearTokens(): void
    {
        session()->forget([
            'kaizen_access_token',
            'kaizen_refresh_token',
            'kaizen_expires_at',
            'kaizen_user',
        ]);
    }

    /**
     * Handle unauthenticated request.
     */
    protected function handleUnauthenticated(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'message' => 'Kaizen authentication required.',
                'error' => 'unauthenticated',
            ], 401);
        }

        return redirect()->route('kaizen.redirect');
    }
}
