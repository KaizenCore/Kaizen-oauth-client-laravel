# Kaizen Laravel OAuth Client

Laravel Socialite provider for Kaizen OAuth authentication.

## Installation

```bash
composer require kaizencore/laravel-oauth-client
```

The package will automatically register itself via Laravel's package auto-discovery.

## Configuration

Add these variables to your `.env` file:

```env
KAIZEN_CLIENT_ID=your-client-id
KAIZEN_CLIENT_SECRET=your-client-secret
```

That's it! The package is ready to use.

### Optional Configuration

```env
# Custom redirect URI (default: /auth/kaizen/callback)
KAIZEN_REDIRECT_URI=/custom/callback

# Custom base URL (default: https://kaizencore.tech)
KAIZEN_BASE_URL=https://kaizencore.tech

# Custom scopes (default: user:read,user:email)
KAIZEN_SCOPES=user:read,user:email,user:profile
```

To publish the config file:

```bash
php artisan vendor:publish --tag=kaizen-config
```

## Usage

### Basic Authentication Flow

```php
use Laravel\Socialite\Facades\Socialite;

// routes/web.php
Route::get('/auth/kaizen', function () {
    return Socialite::driver('kaizen')->redirect();
})->name('kaizen.redirect');

Route::get('/auth/kaizen/callback', function () {
    $user = Socialite::driver('kaizen')->user();

    // $user->getId()
    // $user->getName()
    // $user->getEmail()
    // $user->getAvatar()
    // $user->getMinecraftUuid()
    // $user->getMinecraftUsername()

    // Store tokens in session
    session([
        'kaizen_access_token' => $user->token,
        'kaizen_refresh_token' => $user->refreshToken,
        'kaizen_expires_at' => now()->addSeconds($user->expiresIn),
        'kaizen_user' => [
            'id' => $user->getId(),
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'avatar' => $user->getAvatar(),
        ],
    ]);

    return redirect('/dashboard');
})->name('kaizen.callback');
```

### Custom Scopes

```php
return Socialite::driver('kaizen')
    ->scopes(['user:read', 'user:email', 'api:keys'])
    ->redirect();
```

### Using Default Scopes from Config

```php
return Socialite::driver('kaizen')
    ->withDefaultScopes()
    ->redirect();
```

### Refreshing Tokens

```php
use Laravel\Socialite\Facades\Socialite;

$provider = Socialite::driver('kaizen');
$newTokens = $provider->refreshToken(session('kaizen_refresh_token'));

session([
    'kaizen_access_token' => $newTokens['access_token'],
    'kaizen_refresh_token' => $newTokens['refresh_token'],
    'kaizen_expires_at' => now()->addSeconds($newTokens['expires_in']),
]);
```

### Revoking Tokens

```php
$provider = Socialite::driver('kaizen');
$provider->revokeToken(session('kaizen_access_token'));

session()->forget(['kaizen_access_token', 'kaizen_refresh_token', 'kaizen_expires_at', 'kaizen_user']);
```

### Getting User Profile

```php
$provider = Socialite::driver('kaizen');
$profile = $provider->getUserProfile(session('kaizen_access_token'));
```

## Middleware

The package includes middleware for both web session-based and API token-based authentication.

### Web Session Authentication

For traditional web applications that store tokens in sessions:

```php
// routes/web.php
Route::middleware('kaizen.auth')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});
```

The `kaizen.auth` middleware will:
- Check for a valid Kaizen token in the session
- Automatically refresh expired tokens using the refresh token
- Redirect to the login route if no valid token exists

### API Token Authentication

For API endpoints that receive Bearer tokens in the Authorization header:

```php
// routes/api.php

// Basic authentication - validates the token
Route::middleware('kaizen.api')->group(function () {
    Route::get('/user', fn(Request $request) => $request->attributes->get('kaizen_user'));
});

// With required scopes - user must have ALL specified scopes
Route::middleware('kaizen.api:skins:read,skins:create')->group(function () {
    Route::get('/skins', [SkinController::class, 'index']);
    Route::post('/skins', [SkinController::class, 'store']);
});

// Check for ANY scope - user needs at least one
Route::middleware(['kaizen.api', 'kaizen.scopes.any:skins:read,skins:manage'])->group(function () {
    Route::get('/my-skins', [SkinController::class, 'mySkins']);
});
```

The `kaizen.api` middleware supports two authentication methods:

1. **Bearer Token** (primary): Extract token from `Authorization: Bearer <token>` header
2. **Session Fallback** (for SPAs): Use session-stored tokens when no Bearer token is present

This makes it perfect for:
- External API consumers (use Bearer tokens)
- Same-domain SPAs/dashboards (use session auth automatically)

Features:
- Validates tokens against the Kaizen OAuth server
- Caches validation results (configurable TTL, default 5 minutes)
- Auto-refreshes expired session tokens
- Attaches the authenticated user to the request
- Optionally checks for required scopes

### Accessing the Authenticated User

```php
// In your controller
public function index(Request $request)
{
    $user = $request->attributes->get('kaizen_user');

    // Access user properties
    $user->getId();
    $user->getName();
    $user->getEmail();
    $user->getMinecraftUuid();
    $user->isAdmin();  // Check if user is admin

    // Check scopes
    $scopes = $user->getRaw()['scopes'] ?? [];

    return response()->json([
        'user' => $user->getId(),
        'scopes' => $scopes,
    ]);
}
```

### Available Middleware Aliases

| Alias | Class | Description |
|-------|-------|-------------|
| `kaizen.auth` | `EnsureKaizenToken` | Web session-based auth with auto-refresh |
| `kaizen.api` | `ValidateKaizenToken` | API Bearer token validation |
| `kaizen.scopes` | `CheckKaizenScopes` | Require ALL specified scopes |
| `kaizen.scopes.any` | `CheckKaizenScopesAny` | Require ANY of specified scopes |

## KaizenUser Object

The `KaizenUser` object extends the standard Socialite User with additional methods:

```php
$user = Socialite::driver('kaizen')->user();

// Standard Socialite methods
$user->getId();
$user->getName();
$user->getEmail();
$user->getAvatar();
$user->token;
$user->refreshToken;
$user->expiresIn;

// Kaizen-specific methods
$user->getMinecraftUuid();        // Minecraft UUID if linked
$user->getMinecraftUsername();    // Minecraft username if linked
$user->hasMinecraftAccount();     // Check if Minecraft is linked
$user->hasRole('admin');          // Check user role
$user->isAdmin();                 // Shortcut for admin check
$user->getLocale();               // User's locale preference (en/fr)
$user->getAttribute('key');       // Get any raw attribute
$user->getAttributes();           // Get all raw attributes
```

## Available Scopes

### User Scopes
| Scope | Description |
|-------|-------------|
| `user:read` | Basic user information (id, name, avatar) |
| `user:email` | User's email address |
| `user:profile` | Full profile including Minecraft account info |

### Minecraft Scopes
| Scope | Description |
|-------|-------------|
| `minecraft:read` | Read linked Minecraft account (UUID, username) |
| `minecraft:verify` | Verify Minecraft account ownership |

### Skins API Scopes
| Scope | Description |
|-------|-------------|
| `skins:read` | View user's Minecraft skins |
| `skins:create` | Upload new skins |
| `skins:delete` | Delete skins |
| `skins:manage` | Full access to skins (view, create, edit, delete) |

### API Keys Scopes
| Scope | Description |
|-------|-------------|
| `api-keys:read` | View API keys |
| `api-keys:create` | Create new API keys |
| `api-keys:delete` | Delete API keys |
| `api-keys:manage` | Full access to API keys |

### Other Scopes
| Scope | Description |
|-------|-------------|
| `plugins:favorites` | Manage plugin favorites |

## Getting OAuth Credentials

1. Go to your Kaizen dashboard: https://kaizencore.tech/settings/oauth
2. Create a new OAuth client
3. Set the redirect URI to match your application
4. Copy the Client ID and Client Secret to your `.env` file

## License

MIT
