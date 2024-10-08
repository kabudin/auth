<?php

declare(strict_types=1);

namespace Bud\Auth\Annotation;

use Attribute;
use Hyperf\Di\Annotation\AbstractAnnotation;

#[Attribute(Attribute::TARGET_METHOD)]
class Roles extends AbstractAnnotation
{
    /**
     * 角色权限验证注解
     * @param string|null $codes 角色标识，多个以英文逗号(,)分隔
     * @param string $where 过滤条件 为 OR 时，一票通过 为 AND 时，一票否决
     */
    public function __construct(public ?string $codes = null, public string $where = 'OR')
    {
    }
}
