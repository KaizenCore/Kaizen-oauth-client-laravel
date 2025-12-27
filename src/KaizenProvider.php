<?php

namespace Kaizen\OAuth;

use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;

class KaizenProvider extends AbstractProvider implements ProviderInterface
{
    protected $scopes = ['user:read'];

    protected $scopeSeparator = ' ';

    protected string $baseUrl;

    public function __construct($request, $clientId, $clientSecret, $redirectUrl, string $baseUrl = 'https://kaizencore.tech')
    {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl);
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Get the base URL for Kaizen OAuth.
     */
    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Set the base URL for Kaizen OAuth.
     */
    public function setBaseUrl(string $baseUrl): static
    {
        $this->baseUrl = rtrim($baseUrl, '/');

        return $this;
    }

    /**
     * Get the authentication URL for the provider.
     */
    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->baseUrl.'/oauth/authorize', $state);
    }

    /**
     * Get the token URL for the provider.
     */
    protected function getTokenUrl(): string
    {
        return $this->baseUrl.'/oauth/token';
    }

    /**
     * Get the raw user for the given access token.
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get($this->baseUrl.'/api/v1/user', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
                'Accept' => 'application/json',
            ],
        ]);

        return json_decode($response->getBody(), true)['data'] ?? [];
    }

    /**
     * Map the raw user array to a Socialite User instance.
     */
    protected function mapUserToObject(array $user): KaizenUser
    {
        return (new KaizenUser)->setRaw($user)->map([
            'id' => $user['id'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['avatar_url'] ?? null,
            'minecraft_uuid' => $user['minecraft_uuid'] ?? null,
            'minecraft_username' => $user['minecraft_username'] ?? null,
        ]);
    }

    /**
     * Get the POST fields for the token request.
     */
    protected function getTokenFields($code): array
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    /**
     * Refresh the access token with a refresh token.
     */
    public function refreshToken(string $refreshToken): array
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
            ],
            RequestOptions::FORM_PARAMS => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * Revoke the given access token.
     */
    public function revokeToken(string $token): bool
    {
        try {
            $this->getHttpClient()->delete($this->baseUrl.'/api/v1/token', [
                RequestOptions::HEADERS => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ]);

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the user's full profile with the given access token.
     */
    public function getUserProfile(string $token): array
    {
        $response = $this->getHttpClient()->get($this->baseUrl.'/api/v1/user/profile', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
                'Accept' => 'application/json',
            ],
        ]);

        return json_decode($response->getBody(), true)['data'] ?? [];
    }

    /**
     * Set default scopes from config.
     */
    public function withDefaultScopes(): static
    {
        $scopes = config('kaizen.scopes', ['user:read']);

        return $this->scopes($scopes);
    }

    /**
     * Get the HTTP client instance.
     *
     * Exposed for use by middleware that needs to validate tokens.
     */
    public function httpClient(): \GuzzleHttp\Client
    {
        return $this->getHttpClient();
    }

    /**
     * Validate an access token and return user info if valid.
     *
     * @return array<string, mixed>|null Returns user data with scopes, or null if invalid
     */
    public function validateToken(string $token): ?array
    {
        try {
            $response = $this->getHttpClient()->get($this->baseUrl.'/api/oauth/userinfo', [
                RequestOptions::HEADERS => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ]);

            if ($response->getStatusCode() === 200) {
                return json_decode($response->getBody()->getContents(), true);
            }

            return null;
        } catch (\Exception $e) {
            return null;
        }
    }
}
