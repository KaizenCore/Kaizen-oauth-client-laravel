<?php

namespace Kaizen\OAuth;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Kaizen\OAuth\Http\Middleware\CheckKaizenScopes;
use Kaizen\OAuth\Http\Middleware\CheckKaizenScopesAny;
use Kaizen\OAuth\Http\Middleware\EnsureKaizenToken;
use Kaizen\OAuth\Http\Middleware\ValidateKaizenToken;
use Laravel\Socialite\Facades\Socialite;

class KaizenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/kaizen.php', 'kaizen');

        // Register KaizenProvider as singleton for dependency injection
        $this->app->singleton(KaizenProvider::class, function ($app) {
            $config = $app['config']['kaizen'];

            return new KaizenProvider(
                $app['request'],
                $config['client_id'],
                $config['client_secret'],
                $this->formatRedirectUrl($config),
                $config['base_url'] ?? 'https://kaizencore.tech'
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/kaizen.php' => config_path('kaizen.php'),
        ], 'kaizen-config');

        $this->bootKaizenSocialiteDriver();
        $this->registerMiddleware();
    }

    protected function bootKaizenSocialiteDriver(): void
    {
        Socialite::extend('kaizen', function ($app) {
            return $app->make(KaizenProvider::class);
        });
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        // Web session-based auth
        $router->aliasMiddleware('kaizen.auth', EnsureKaizenToken::class);

        // API token-based auth
        $router->aliasMiddleware('kaizen.api', ValidateKaizenToken::class);

        // Scope checking (use after kaizen.api)
        $router->aliasMiddleware('kaizen.scopes', CheckKaizenScopes::class);
        $router->aliasMiddleware('kaizen.scopes.any', CheckKaizenScopesAny::class);
    }

    protected function formatRedirectUrl(array $config): string
    {
        $redirect = $config['redirect'] ?? '/auth/kaizen/callback';

        // If it's already a full URL, return as-is
        if (str_starts_with($redirect, 'http://') || str_starts_with($redirect, 'https://')) {
            return $redirect;
        }

        // Otherwise, prepend the app URL
        return rtrim(config('app.url'), '/').$redirect;
    }
}
