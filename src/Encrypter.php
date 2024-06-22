<?php

declare(strict_types=1);
/**
 * This file is part of qbhy/simple-jwt.
 *
 * @link     https://github.com/qbhy/simple-jwt
 * @document https://github.com/qbhy/simple-jwt/blob/master/README.md
 * @contact  qbhy0715@qq.com
 * @license  https://github.com/qbhy/simple-jwt/blob/master/LICENSE
 */
namespace Bud\Auth;

interface Encrypter
{
    /**
     * 生成签名
     * @param string $signatureString 待签名字符串
     * @return false|string
     */
    public function signature(string $signatureString): false|string;

    /**
     * 验证签名
     * @param string $signatureString 待签名字符串
     * @param string $signature 签名比对值
     * @return bool
     */
    public function check(string $signatureString, string $signature): bool;

    /**
     * 算法标识
     * @return string
     */
    public static function alg(): string;
}
