<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace Bud\Auth;

use Bud\Auth\Aspect\AuthAnnotationAspect;
use Bud\Auth\Aspect\PermissionAnnotationAspect;
use Bud\Auth\Aspect\RolesAnnotationAspect;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                AuthInterface::class => TokenAuth::class
            ],
            'aspects' => [
                AuthAnnotationAspect::class,
                RolesAnnotationAspect::class,
                PermissionAnnotationAspect::class
            ],
            'publish' => [
                [
                    'id' => 'auth',
                    'description' => 'auth 组件配置.', // 描述
                    // 建议默认配置放在 publish 文件夹中，文件命名和组件名称相同
                    'source' => __DIR__ . '/../publish/bud_auth.php',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/config/autoload/bud_auth.php', // 复制为这个路径下的该文件
                ],
            ],
        ];
    }
}
