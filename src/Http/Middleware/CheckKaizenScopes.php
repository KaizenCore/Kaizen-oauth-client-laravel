<?php

namespace Kaizen\OAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to check if the authenticated Kaizen user has required scopes.
 *
 * This middleware should be used AFTER ValidateKaizenToken.
 *
 * Usage:
 *   Route::middleware(['kaizen.api', 'kaizen.scopes:skins:manage'])->group(...);
 *
 *   // Check for ANY of the scopes (user needs at least one):
 *   Route::middleware('kaizen.scopes.any:skins:read,skins:manage')->get(...);
 */
class CheckKaizenScopes
{
    /**
     * Handle an incoming request - requires ALL specified scopes.
     */
    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $user = $request->get('kaizen_user');

        if (! $user) {
            return response()->json([
                'error' => 'unauthorized',
                'message' => 'No authenticated Kaizen user found.',
            ], 401);
        }

        $userScopes = $user->getRaw()['scopes'] ?? [];

        foreach ($scopes as $requiredScope) {
            if (! in_array($requiredScope, $userScopes)) {
                return response()->json([
                    'error' => 'forbidden',
                    'message' => "Missing required scope: {$requiredScope}",
                    'required_scopes' => $scopes,
                    'user_scopes' => $userScopes,
                ], 403);
            }
        }

        return $next($request);
    }
}
