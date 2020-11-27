<?php namespace LucaDegasperi\OAuth2Server;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use LucaDegasperi\OAuth2Server\Filters\CheckAuthorizationParamsFilter;
use LucaDegasperi\OAuth2Server\Filters\OAuthFilter;
use LucaDegasperi\OAuth2Server\Filters\OAuthOwnerFilter;
use LucaDegasperi\OAuth2Server\Proxies\AuthorizationServerProxy;

class OAuth2ServerServiceProvider extends ServiceProvider
{

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        //$this->package('lucadegasperi/oauth2-server-laravel', 'lucadegasperi/oauth2-server-laravel');

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app['router'];


        $router = $this->app->make(Router::class);

        // Bind a filter to check if the auth code grant type params are provided
        $router->aliasMiddleware('check-authorization-params', CheckAuthorizationParamsFilter::class);
        //$router->filter('check-authorization-params', 'LucaDegasperi\OAuth2Server\Filters\CheckAuthorizationParamsFilter');

        // Bind a filter to make sure that an endpoint is accessible only by authorized members eventually with specific scopes
        $router->aliasMiddleware('oauth', OAuthFilter::class);
        //$router->filter('oauth', 'LucaDegasperi\OAuth2Server\Filters\OAuthFilter');

        // Bind a filter to make sure that an endpoint is accessible only by a specific owner
        $router->aliasMiddleware('oauth-owner', OAuthOwnerFilter::class);
        //$router->filter('oauth-owner', 'LucaDegasperi\OAuth2Server\Filters\OAuthOwnerFilter');


        $this->publishes([
            __DIR__.'/../../config/oauth2.php' => config_path('oauth2.php'),
        ]);
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../../config/oauth2.php', 'oauth2'
        );

        // let's bind the interfaces to the implementations
        $app = $this->app;

        $app->bind('League\OAuth2\Server\Storage\ClientInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentClient');
        $app->bind('League\OAuth2\Server\Storage\ScopeInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentScope');
        $app->bind('League\OAuth2\Server\Storage\SessionInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentSession');
        $app->bind('LucaDegasperi\OAuth2Server\Repositories\SessionManagementInterface', 'LucaDegasperi\OAuth2Server\Repositories\FluentSession');

        $this->app->bind('oauth2.authorization-server', function($app) {

            $server = $app->make('League\OAuth2\Server\Authorization');

            $config = $app['config']->get('oauth2');

            // add the supported grant types to the authorization server
            foreach ($config['grant_types'] as $grantKey => $grantValue) {

                $server->addGrantType(new $grantValue['class']($server));
                $server->getGrantType($grantKey)->setAccessTokenTTL($grantValue['access_token_ttl']);

                if (array_key_exists('callback', $grantValue)) {
                    $server->getGrantType($grantKey)->setVerifyCredentialsCallback($grantValue['callback']);
                }
                if (array_key_exists('auth_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setAuthTokenTTL($grantValue['auth_token_ttl']);
                }
                if (array_key_exists('refresh_token_ttl', $grantValue)) {
                    $server->getGrantType($grantKey)->setRefreshTokenTTL($grantValue['refresh_token_ttl']);
                }
                if (array_key_exists('rotate_refresh_tokens', $grantValue)) {
                    $server->getGrantType($grantKey)->rotateRefreshTokens($grantValue['rotate_refresh_tokens']);
                }
            }

            $server->requireStateParam($config['state_param']);

            $server->requireScopeParam($config['scope_param']);

            $server->setScopeDelimeter($config['scope_delimiter']);

            $server->setDefaultScope($config['default_scope']);

            $server->setAccessTokenTTL($config['access_token_ttl']);

            return new AuthorizationServerProxy($server);

        });

        $this->app->bind('oauth2.resource-server', function($app) {

            $server = $app->make('League\OAuth2\Server\Resource');

            return $server;

        });

        $this->app->bind('oauth2.expired-tokens-command', function($app) {
            return $app->make('LucaDegasperi\OAuth2Server\Commands\ExpiredTokensCommand');
        });

        $this->commands('oauth2.expired-tokens-command');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return array('oauth2.authorization-server', 'oauth2.resource-server');
    }
}
