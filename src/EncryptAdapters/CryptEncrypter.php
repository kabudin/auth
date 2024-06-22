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

namespace Bud\Auth\EncryptAdapters;

use Bud\Auth\AbstractEncrypter;

class CryptEncrypter extends AbstractEncrypter
{
    public function signature(string $signatureString): string
    {
        return crypt($signatureString, $this->getSecret());
    }

    /**
     * @return string php-crypt
     */
    public static function alg(): string
    {
        return 'php-crypt';
    }
}
