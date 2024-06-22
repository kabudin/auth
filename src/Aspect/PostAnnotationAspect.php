<?php
declare(strict_types=1);

namespace Bud\Auth\Aspect;

use Bud\Auth\Annotation\Post;
use Bud\Auth\Exception\PermissionException;
use Hyperf\Di\Aop\AbstractAspect;
use Hyperf\Di\Aop\ProceedingJoinPoint;
use Hyperf\Di\Exception\Exception;

class PostAnnotationAspect extends AbstractAspect
{
    public array $annotations = [Post::class];

    /**
     * @param ProceedingJoinPoint $proceedingJoinPoint
     * @return mixed
     * @throws Exception
     */
    public function process(ProceedingJoinPoint $proceedingJoinPoint): mixed
    {
        /** @var Post $roles */
        if (isset($proceedingJoinPoint->getAnnotationMetadata()->method[Post::class])) {
            $posts = $proceedingJoinPoint->getAnnotationMetadata()->method[Post::class];
        }
        // 权限校验
        if (empty($posts->codes)) {
            return $proceedingJoinPoint->process();
        }
        $codeList = auth($roles->scene)?->getUserPostCodes() ?? [];
        // 当条件为 OR 时有一个权限则放行（交集不为空）
        if ($posts->where === 'OR' && !empty(array_intersect(explode(',', $posts->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        // 当条件为 AND 时同时拥有所有权限才放行（差集为空）
        if ($posts->where === 'AND' && empty(array_diff(explode(',', $posts->codes), $codeList))) {
            return $proceedingJoinPoint->process();
        }
        $tip = $posts->where === 'AND' ? '同时属于' : '属于任意';
        $message = "当前操作必须{$tip}以下岗位：" . implode(',',$codeList);
        throw new PermissionException($message);
    }
}