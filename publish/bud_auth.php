<?php

declare(strict_types=1);

use Bud\Auth\EncryptAdapters as Encrypter;
use function Hyperf\Support\env;

$drivers = [
    Encrypter\PasswordHashEncrypter::alg() => Encrypter\PasswordHashEncrypter::class,
    Encrypter\CryptEncrypter::alg() => Encrypter\CryptEncrypter::class,
    Encrypter\SHA1Encrypter::alg() => Encrypter\SHA1Encrypter::class,
    Encrypter\Md5Encrypter::alg() => Encrypter\Md5Encrypter::class,
];
return [
    'scenes' => [
        'admin' => [
            // redis连接池
            'redis_pool' => 'default',
            // token秘钥，根据加密类的实现该配置可以为数组。默认仅实现了对称加密，所以默认为字符串
            'secret' => env('TOKEN_SECRET', 'MIIEvAIBADANBekkiG9w0BAQEFAASCBKYeggSiAgEAAoIBAQCW088oDryly0xqCh=='),
            // 请求头token使用的字段
            'header_name' => env('TOKEN_HEADER_NAME', 'Authorization'),
            // token 生命周期，单位秒，默认一天
            'ttl' => (int)env('TOKEN_TTL', 60 * 60 * 24),
            // 自token过期开始多长时间内允许自动刷新，小于1则不允许刷新。默认2小时
            'refresh_ttl' => (int)env('TOKEN_REFRESH_TTL', 60 * 60 * 2),
            // 是否自动刷新，仅在使用Auth注解下生效
            'auto_refresh' => true,
            // 自动刷新重试次数，不建议过大默认2次
            'retry' => 2,
            // 自动刷新重试等待时间（秒），默认1秒
            'retry_time' => 1,
            // 实现了 \Bud\Auth\UserInterface 接口的类。
            // 为空时无法通过auth()直接获取当前登录用户的详细信息，以及操作权限、角色权限、岗位权限的注解鉴权
            'service' => '',
            // 默认使用的加密类,alg算法标识|完整类名
            'encryptor' => Encrypter\PasswordHashEncrypter::class,
            // 可选加密类。加密类必须实现 \Bud\Auth\Manager\Encrypter 接口
            'drivers' => $drivers,
        ],
    ]
];
