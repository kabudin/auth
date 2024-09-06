<?php

declare (strict_types=1);

namespace Bud\Auth\Aspect;

use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Bud\Auth\Annotation\Roles;
use Bud\Auth\Exception\PermissionException;
use Hyperf\Di\Exception\Exception;

/**
 * 角色权限拦截AOP
 */
class RolesAnnotationAspect extends AbstractAspect
{
    public array $annotations = [Roles::class];

    /**
     * @param ProceedingJoinPoint $proceedingJoinPoint
     * @return mixed
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        /** @var Roles $roles */
        if (isset($proceedingJoinPoint->getAnnotationMetadata()->method[Roles::class])) {
            $roles = $proceedingJoinPoint->getAnnotationMetadata()->method[Roles::class];
        }
        // 权限校验
        if (empty($roles->codes)) {
            return $proceedingJoinPoint->process();
        }
        $codeList = auth()->user()?->getRoleCodes() ?? [];
        // 当条件为 OR 时有一个权限则放行（交集不为空）
        if ($roles->where === 'OR' && !empty(array_intersect(explode(',', $roles->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        // 当条件为 AND 时同时拥有所有权限才放行（差集为空）
        if ($roles->where === 'AND' && empty(array_diff(explode(',', $roles->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        $tip = $roles->where === 'AND' ? '同时拥有' : '拥有任意';
        $message = "当前操作必须{$tip}以下角色：" . implode(',',$codeList);
        throw new PermissionException($message);
    }
}
