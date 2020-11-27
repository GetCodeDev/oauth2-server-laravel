<?php namespace LucaDegasperi\OAuth2Server\Filters;

use ResourceServer;
use Response;
use Closure;

class OAuthOwnerFilter
{

    /**
     * @param         $request
     * @param Closure $next
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function handle($request, Closure $next)
    {   
        if (func_num_args() > 2) {
            $owner_types = array_slice(func_get_args(), 2);
            if(!in_array(ResourceServer::getOwnerType(), $owner_types)) {
                return Response::json(array(
                    'status' => 403,
                    'error' => 'forbidden',
                    'error_message' => 'Only access tokens representing ' . implode(',', $owner_types) . ' can use this endpoint',
                ), 403);
            }
        }
    }
}
