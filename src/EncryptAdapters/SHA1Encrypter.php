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

class SHA1Encrypter extends AbstractEncrypter
{
    public function signature(string $signatureString): string
    {
        return hash('sha1', $signatureString . $this->getSecret());
    }

    /**
     * @return string sha1
     */
    public static function alg(): string
    {
        return 'sha1';
    }
}
