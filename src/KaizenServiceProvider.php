<?php

namespace Kaizen\OAuth;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;

class KaizenServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/kaizen.php', 'kaizen');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/kaizen.php' => config_path('kaizen.php'),
        ], 'kaizen-config');

        $this->bootKaizenSocialiteDriver();
    }

    protected function bootKaizenSocialiteDriver(): void
    {
        Socialite::extend('kaizen', function ($app) {
            $config = $app['config']['kaizen'];

            return new KaizenProvider(
                $app['request'],
                $config['client_id'],
                $config['client_secret'],
                $this->formatRedirectUrl($config),
                $config['base_url'] ?? 'https://kaizenmc.fr'
            );
        });
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
