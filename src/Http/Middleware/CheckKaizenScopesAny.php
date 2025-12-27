<?php

namespace Kaizen\OAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to check if the authenticated Kaizen user has ANY of the required scopes.
 *
 * This middleware should be used AFTER ValidateKaizenToken.
 *
 * Usage:
 *   // User needs at least ONE of these scopes:
 *   Route::middleware(['kaizen.api', 'kaizen.scopes.any:skins:read,skins:manage'])->get(...);
 */
class CheckKaizenScopesAny
{
    /**
     * Handle an incoming request - requires ANY of the specified scopes.
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

        foreach ($scopes as $allowedScope) {
            if (in_array($allowedScope, $userScopes)) {
                return $next($request);
            }
        }

        return response()->json([
            'error' => 'forbidden',
            'message' => 'You need at least one of the required scopes.',
            'required_scopes' => $scopes,
            'user_scopes' => $userScopes,
        ], 403);
    }
}
