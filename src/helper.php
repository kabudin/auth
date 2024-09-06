<?php
declare(strict_types=1);

use Bud\Auth\AuthInterface;
use Bud\Auth\TokenAuth;
use function Hyperf\Support\make;

if (! function_exists('auth')) {
    /**
     * 获取一个Auth对象
     * @param string|null $scene 默认值 admin
     * @return mixed
     */
    function auth(?string $scene = null): AuthInterface
    {
        if ($scene){
            return make(TokenAuth::class)->scene($scene);
        }
        return make(TokenAuth::class);
    }
}