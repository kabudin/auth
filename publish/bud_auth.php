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
    // 请求头token使用的字段
    'header_name' => env('TOKEN_HEADER_NAME', 'Authorization'),
    'scenes' => [
        'admin' => [
            // 超级管理员ID, 注意非管理员场景不可设置该值，
            'super_admin' => 1,
            // token秘钥，根据加密类的实现该配置可以为数组。默认仅实现了对称加密，所以默认为字符串
            'secret' => env('TOKEN_SECRET', 'MIIEvAIBADANBekkiG9w0BAQEFAASCBKYeggSiAgEAAoIBAQCW088oDryly0xqCh=='),
            // token 生命周期，单位秒，默认一天
            'ttl' => (int)env('TOKEN_TTL', 60 * 60 * 24),
            // 是否单点登录,为true时一个token可以在多个设备同时使用，默认多点登录
            'single' => true,
            // 自token过期开始多长时间内允许自动刷新，小于1则不允许刷新。默认2小时
            'refresh_ttl' => (int)env('TOKEN_REFRESH_TTL', 60 * 60 * 2),
            // 是否自动刷新，仅在使用Auth注解下生效
            'auto_refresh' => true,
            // 默认使用的加密类,alg算法标识|完整类名
            'encryptor' => Encrypter\PasswordHashEncrypter::class,
            // 可选加密类。加密类必须实现 \Bud\Auth\Manager\Encrypter 接口
            'drivers' => $drivers,
        ],
    ]
];
