<?php
declare(strict_types=1);

use Hyperf\Context\ApplicationContext;
use Bud\Auth\AuthInterface;
use Bud\Auth\AuthManager;

if (! function_exists('auth')) {
    /**
     * 获取一个Auth对象
     * @param string|null $scene
     * @return mixed
     */
    function auth(?string $scene = 'admin'): AuthInterface
    {
        return ApplicationContext::getContainer()->get(AuthManager::class)->scene($scene);
    }
}