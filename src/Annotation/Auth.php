<?php
declare(strict_types=1);

namespace Bud\Auth\Annotation;

use Attribute;
use Hyperf\Di\Annotation\AbstractAnnotation;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class Auth extends AbstractAnnotation
{
    /**
     * 验证用户是否登录
     * @param string $scene 验证场景
     */
    public function __construct(public string $scene = 'admin')
    {
    }
}
