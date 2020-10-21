<?php namespace LucaDegasperi\OAuth2Server\Filters;

use ResourceServer;
use Response;
use Config;
use Closure;

class OAuthFilter
{

    /**
     * @param         $request
     * @param Closure $next
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function handle($request, Closure $next)
    {
        try {
            ResourceServer::isValid(config('oauth2.http_headers_only'));

            return $next($request);
        } catch (\League\OAuth2\Server\Exception\InvalidAccessTokenException $e) {
            return Response::json(array(
                'status' => 401,
                'error' => 'unauthorized',
                'error_message' => $e->getMessage(),
            ), 401);
        }
        
        if (func_num_args() > 2) {
            $args = func_get_args();
            $scopes = array_slice($args, 2);

            foreach ($scopes as $s) {
                if (! ResourceServer::hasScope($s)) {
                    return Response::json(array(
                        'status' => 403,
                        'error' => 'forbidden',
                        'error_message' => 'Only access token with scope '.$s.' can use this endpoint',
                    ), 403);
                }
            }
        }
    }
}
