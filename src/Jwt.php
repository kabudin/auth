<?php
declare(strict_types=1);

namespace Bud\Auth;

use Bud\Auth\Exception\AuthException;
use Bud\Auth\EncryptAdapters\PasswordHashEncrypter;
use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Stringable\Str;

class Jwt
{
    protected string $scene = 'admin';

    protected array $headers = [
        'typ' => 'jwt',
    ];

    protected array $payload = [];

    public function __construct(protected ConfigInterface $config)
    {
    }

    /**
     * 获取auth配置
     * @param string|null $key 存在获取当前场景下的指定配置，否则获取当前场景所有
     * @return mixed
     */
    public function getConfig(?string $key = null): mixed
    {
        if (!empty($key)) {
            return $this->config->get("bud_auth.scenes.$this->scene.$key");
        }
        return $this->config->get("bud_auth.scenes.$this->scene");
    }

    /**
     * 获取加密器
     * @return AbstractEncrypter|Encrypter
     */
    protected function getEncryptor(): AbstractEncrypter|Encrypter
    {
        $encryptor = $this->getConfig('encryptor') ?? PasswordHashEncrypter::class;
        $secret = $this->getConfig('secret');
        if (class_exists($encryptor)) {
            return new $encryptor($secret);
        }
        if (isset($this->getDrivers[$encryptor]) && class_exists($this->getDrivers[$encryptor])) {
            return new $this->getDrivers[$encryptor]($secret);
        } else {
            return new PasswordHashEncrypter($secret);
        }
    }

    /**
     * 获取jwt头信息
     * @param string|null $key 为空获取整个 headers 数组
     * @return mixed
     */
    public function getHeader(?string $key = null): mixed
    {
        if (empty($key)) return $this->headers;
        return $this->headers[$key] ?? null;
    }

    /**
     * 获取jwt负载信息
     * @param string|null $key 为空获取整个 payload 数组
     * @return mixed
     */
    public function getPayload(?string $key = null): mixed
    {
        if (empty($key)) return $this->payload;
        return $this->payload[$key] ?? null;
    }

    /**
     * @param array $headers
     * @return Jwt
     */
    protected function setHeaders(array $headers): static
    {
        $this->headers = $headers;
        return $this;
    }

    /**
     * @param string $key
     * @param $value
     * @return $this
     */
    public function addHeaders(string $key, $value): static
    {
        $this->headers[$key] = $value;
        return $this;
    }

    /**
     * @param array $payload
     * @return Jwt
     */
    public function setPayload(array $payload): static
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @param string $key
     * @param $value
     * @return Jwt
     */
    public function addPayload(string $key, $value): static
    {
        $this->payload[$key] = $value;
        return $this;
    }

    /**
     * @return string
     */
    public function getScene(): string
    {
        return $this->scene;
    }

    /**
     * @param string $scene
     * @return Jwt
     */
    public function setScene(string $scene): static
    {
        $this->scene = $scene;
        return $this;
    }

    /**
     * 编码字符串
     * @param string $string
     * @return string
     */
    protected function encode(string $string): string
    {
        return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
    }

    /**
     * 解码字符串
     * @param string $string
     * @return string
     */
    protected function decode(string $string): string
    {
        return base64_decode(strtr($string, '-_', '+/'));
    }

    /**
     * 生成签名字符串
     * @return string
     */
    protected function generateSignatureString(): string
    {
        $headersString = $this->encode(json_encode($this->headers));
        $payloadString = $this->encode(json_encode($this->payload));
        return "$headersString.$payloadString";
    }

    /**
     * 生成token字符串
     * @return string
     */
    public function getToken(): string
    {
        $this->addHeaders('sce', $this->getScene());
        $signatureString = $this->generateSignatureString();
        $signature = $this->encode(
            $this->getEncryptor()->signature($signatureString)
        );
        $token = "{$signatureString}.{$signature}";
        Context::set('__auth__:login:token', $token);
        return $token;
    }

    /**
     * 解析一个token.
     * @param string $token
     * @param bool $checkSign 是否验证签名，默认true
     * @return Jwt
     */
    public function justParse(string $token, bool $checkSign = true): static
    {
        if (Str::startsWith($token, 'Bearer ')) {
            $token = Str::substr($token, 7);
        }
        $arr = explode('.', $token);
        if (count($arr) !== 3) {
            throw new AuthException('Invalid token');
        }
        $headers = @json_decode($this->decode($arr[0]), true);
        $payload = @json_decode($this->decode($arr[1]), true);
        $signatureString = "{$arr[0]}.{$arr[1]}";
        if (!is_array($headers) || !is_array($payload)) {
            throw new AuthException('Invalid token');
        }
        $this->setHeaders($headers)->setPayload($payload)->setScene($headers['sce']);
        if (!$checkSign || $this->getEncryptor()->check($signatureString, $this->decode($arr[2]))) {
            return $this;
        }
        throw new AuthException('Invalid signature');
    }
}