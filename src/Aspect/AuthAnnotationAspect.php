<?php

declare (strict_types=1);

namespace Bud\Auth\Aspect;

use Hyperf\Context\Context;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Di\Exception\Exception;
use Psr\Http\Message\ResponseInterface;
use Bud\Auth\Annotation\Auth;
use Bud\Auth\Exception\TokenExpiredException;

/**
 * 登录权限拦截AOP
 */
class AuthAnnotationAspect extends AbstractAspect
{
    public array $annotations = [Auth::class];

    /**
     * @param ProceedingJoinPoint $proceedingJoinPoint
     * @return mixed
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        try {
            auth()->check();
        } catch (TokenExpiredException $e) {
            $jwt = $e->getJwt();
            if ($jwt->getConfig()['auto_refresh']){
                $newToken = auth($jwt->getScene())->refresh($jwt);
                $response = Context::get(ResponseInterface::class);
                $response = $response->withHeader($jwt->getConfig()['header_name'] ?? 'Authorization', 'Bearer ' . $newToken);
                Context::set(ResponseInterface::class, $response);
            }else{
                throw $e;
            }
        }
        return $proceedingJoinPoint->process();
    }
}
