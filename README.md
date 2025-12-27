# Kaizen Laravel OAuth Client

Laravel Socialite provider for Kaizen OAuth authentication.

## Installation

```bash
composer require kaizen/laravel-oauth-client
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

# Custom base URL (default: https://kaizenmc.fr)
KAIZEN_BASE_URL=https://kaizenmc.fr

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

The package includes a middleware to protect routes that require Kaizen authentication:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias([
        'kaizen.auth' => \Kaizen\OAuth\Http\Middleware\EnsureKaizenToken::class,
    ]);
})

// routes/web.php
Route::middleware('kaizen.auth')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});
```

The middleware will:
- Check for a valid Kaizen token in the session
- Automatically refresh expired tokens using the refresh token
- Redirect to the login route if no valid token exists

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

1. Go to your Kaizen dashboard: https://kaizenmc.fr/settings/oauth
2. Create a new OAuth client
3. Set the redirect URI to match your application
4. Copy the Client ID and Client Secret to your `.env` file

## License

MIT
