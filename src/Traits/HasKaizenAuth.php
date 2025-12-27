<?php

namespace Kaizen\OAuth\Traits;

use Kaizen\OAuth\KaizenUser;
use Laravel\Socialite\Facades\Socialite;

trait HasKaizenAuth
{
    /**
     * Get the current Kaizen access token.
     */
    protected function getKaizenToken(): ?string
    {
        return session('kaizen_access_token');
    }

    /**
     * Get the current Kaizen user from session.
     */
    protected function getKaizenUser(): ?array
    {
        return session('kaizen_user');
    }

    /**
     * Check if the user is authenticated with Kaizen.
     */
    protected function isKaizenAuthenticated(): bool
    {
        $token = $this->getKaizenToken();
        $expiresAt = session('kaizen_expires_at');

        if (! $token) {
            return false;
        }

        if ($expiresAt && now()->greaterThan($expiresAt)) {
            return $this->tryRefreshKaizenToken();
        }

        return true;
    }

    /**
     * Try to refresh the Kaizen token.
     */
    protected function tryRefreshKaizenToken(): bool
    {
        $refreshToken = session('kaizen_refresh_token');

        if (! $refreshToken) {
            return false;
        }

        try {
            $provider = Socialite::driver('kaizen');
            $newTokens = $provider->refreshToken($refreshToken);

            session([
                'kaizen_access_token' => $newTokens['access_token'],
                'kaizen_refresh_token' => $newTokens['refresh_token'] ?? $refreshToken,
                'kaizen_expires_at' => now()->addSeconds($newTokens['expires_in'] ?? 3600),
            ]);

            return true;
        } catch (\Exception $e) {
            $this->clearKaizenSession();

            return false;
        }
    }

    /**
     * Store Kaizen OAuth tokens and user in session.
     */
    protected function storeKaizenAuth(KaizenUser $user): void
    {
        session([
            'kaizen_access_token' => $user->token,
            'kaizen_refresh_token' => $user->refreshToken,
            'kaizen_expires_at' => now()->addSeconds($user->expiresIn ?? 3600),
            'kaizen_user' => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail(),
                'avatar' => $user->getAvatar(),
                'minecraft_uuid' => $user->getMinecraftUuid(),
                'minecraft_username' => $user->getMinecraftUsername(),
                'raw' => $user->getAttributes(),
            ],
        ]);
    }

    /**
     * Revoke the current token and clear session.
     */
    protected function revokeKaizenAuth(): void
    {
        $token = $this->getKaizenToken();

        if ($token) {
            try {
                $provider = Socialite::driver('kaizen');
                $provider->revokeToken($token);
            } catch (\Exception $e) {
                // Ignore errors when revoking
            }
        }

        $this->clearKaizenSession();
    }

    /**
     * Clear all Kaizen session data.
     */
    protected function clearKaizenSession(): void
    {
        session()->forget([
            'kaizen_access_token',
            'kaizen_refresh_token',
            'kaizen_expires_at',
            'kaizen_user',
        ]);
    }
}
