<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Kaizen OAuth Configuration
    |--------------------------------------------------------------------------
    |
    | Configure your Kaizen OAuth client credentials here. You can obtain
    | these from your Kaizen dashboard at https://kaizencore.tech/settings/oauth
    |
    */

    'client_id' => env('KAIZEN_CLIENT_ID'),
    'client_secret' => env('KAIZEN_CLIENT_SECRET'),
    'redirect' => env('KAIZEN_REDIRECT_URI', '/auth/kaizen/callback'),

    /*
    |--------------------------------------------------------------------------
    | Kaizen Base URL
    |--------------------------------------------------------------------------
    |
    | The base URL of the Kaizen OAuth server. You typically don't need to
    | change this unless you're running a local development instance.
    |
    */

    'base_url' => env('KAIZEN_BASE_URL', 'https://kaizencore.tech'),

    /*
    |--------------------------------------------------------------------------
    | Token Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long to cache validated access tokens (in seconds). This reduces
    | the number of validation requests to the Kaizen OAuth server.
    | Set to 0 to disable caching.
    |
    */

    'token_cache_ttl' => env('KAIZEN_TOKEN_CACHE_TTL', 300),

    /*
    |--------------------------------------------------------------------------
    | Default Scopes
    |--------------------------------------------------------------------------
    |
    | The default scopes to request when authenticating. Available scopes:
    |
    | User scopes:
    | - user:read       : Basic user information (id, name, avatar)
    | - user:email      : User's email address
    | - user:profile    : Full profile including Minecraft account info
    |
    | Minecraft scopes:
    | - minecraft:read  : Read linked Minecraft account (UUID, username)
    | - minecraft:verify: Verify Minecraft account ownership
    |
    | Skins API scopes:
    | - skins:read      : View user's Minecraft skins
    | - skins:create    : Upload new skins
    | - skins:delete    : Delete skins
    | - skins:manage    : Full access to skins (view, create, edit, delete)
    |
    | API Keys scopes:
    | - api-keys:read   : View API keys
    | - api-keys:create : Create new API keys
    | - api-keys:delete : Delete API keys
    | - api-keys:manage : Full access to API keys
    |
    | Other scopes:
    | - plugins:favorites : Manage plugin favorites
    |
    */

    'scopes' => explode(',', env('KAIZEN_SCOPES', 'user:read,user:email')),
];
