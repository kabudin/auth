<?php

declare (strict_types=1);

namespace Bud\Auth\Aspect;

use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Bud\Auth\Annotation\Permission;
use Bud\Auth\Exception\PermissionException;
use Hyperf\Di\Exception\Exception;

/**
 * 操作权限拦截AOP
 */
class PermissionAnnotationAspect extends AbstractAspect
{
    public array $annotations = [Permission::class];

    /**
     * @param ProceedingJoinPoint $proceedingJoinPoint
     * @return mixed
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        /** @var Permission $permission */
        if (isset($proceedingJoinPoint->getAnnotationMetadata()->method[Permission::class])) {
            $permission = $proceedingJoinPoint->getAnnotationMetadata()->method[Permission::class];
        }
        // 权限校验
        if (empty($permission->codes) || auth()->isSuperAdmin()) {
            return $proceedingJoinPoint->process();
        }
        $codeList = auth()->user()->getPermissionCodes() ?? [];
        // 当条件为 OR 时有一个权限则放行（交集不为空）
        if ($permission->where === 'OR' && !empty(array_intersect(explode(',', $permission->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        // 当条件为 AND 时同时拥有所有权限才放行（差集为空）
        if ($permission->where === 'AND' && empty(array_diff(explode(',', $permission->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        throw new PermissionException('no permission.');
    }
}
