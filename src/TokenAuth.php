<?php
declare(strict_types=1);

namespace Bud\Auth;

use Bud\Auth\Exception\TokenExpiredException;
use Hyperf\Context\Context;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Stringable\Str;
use Bud\Auth\Exception\AuthException;
use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use function Hyperf\Support\make;

class TokenAuth implements AuthInterface
{
    protected Jwt $jwt;

    protected CacheInterface $cache;

    protected string $headerName = 'Authorization';

    public function __construct(protected ContainerInterface $container, protected RequestInterface $request)
    {
        $this->jwt = make(Jwt::class);
        $config = $container->get(ConfigInterface::class);
        $this->cache = $container->get(CacheInterface::class);
        $this->headerName = $config->get('bud_auth.header_name', 'Authorization');
    }

    /**
     * 初始化一个JWT场景
     * @param string $scene
     * @return $this
     */
    public function scene(string $scene = 'admin'): TokenAuth
    {
        $this->jwt->setScene($scene);
        return $this;
    }

    /**
     * 从请求中解析token
     * @return mixed
     */
    protected function parseToken(): mixed
    {
        // 首先判断上下文中是否存在刷新token，如果存在则使用新token
        if (Context::has('__auth__:refresh:token'))
            return Context::get('__auth__:refresh:token');
        // 然后判断上下文中是否存在登录token，如果存在则使用登录token
        if (Context::has('__auth__:login:token'))
            return Context::get('__auth__:login:token');
        // 最后从请求中解析token
        $token = $this->request->header($this->headerName, '');
        if (!empty($token)) {
            if (Str::startsWith($token, 'Bearer ')) {
                return Str::substr($token, 7);
            }
            return $token;
        }
        if ($this->request->has('token')) {
            return $this->request->input('token');
        }
        return null;
    }

    /**
     * 登录,返回token字符串
     * @param UserInterface $user
     * @param array $payload
     * @return string
     */
    public function login(UserInterface $user, array $payload = []): string
    {
        $jwt = $this->parseLogin($user, $payload);
        return $jwt->getToken();
    }

    /**
     * 登录，返回jwt对象
     * @param UserInterface $user
     * @param array $payload
     * @return Jwt
     */
    public function parseLogin(UserInterface $user, array $payload = []): Jwt
    {
        $timestamp = time();
        $secret = $this->jwt->getConfig('secret');
        $ttl = $this->jwt->getConfig('ttl') ?? 60 * 60 * 24;
        $refresh_ttl = $this->jwt->getConfig('refresh_ttl') ?? 60 * 60 * 2; // 默认2小时内可以刷新
        $age = md5($this->request->getHeader('user-agent')[0] . $this->jwt->getConfig('secret'));
        $jwt = $this->jwt->setPayload($payload)
            ->addPayload('sub', $user->getId()) // 设置所属用户
            ->addPayload('iat', $timestamp) // 签发时间
            ->addPayload('exp', $timestamp + $ttl) // 过期时间
            ->addPayload('iss', $this->request->getHeader('host')[0]) // 设置签发者
            ->addHeaders('age', $age);
        $jti = hash('md5', base64_encode(json_encode([$this->jwt->getPayload(), $this->jwt->getHeader()])) . $secret);
        $jwt->addHeaders('jti', $jti);
        $cache_key = $jwt->getScene() . '_' . $user->getId();
        $this->cache->set("auth_$cache_key", $user, $timestamp + $ttl + $refresh_ttl);
        return $jwt;
    }

    /**
     * 强制退出某个用户
     * @param string $scene
     * @param UserInterface $user
     * @return bool
     * @throws InvalidArgumentException
     */
    public function forceExit(string $scene, UserInterface $user): bool
    {
        $this->cache->delete("auth_{$scene}_{$user->getId()}");
        return true;
    }

    /**
     * 将token添加到黑名单
     * @param Jwt|string $jwt jwt对象或者jti标识
     * @return bool
     * @throws InvalidArgumentException
     */
    private function addBlacklist(Jwt|string $jwt): bool
    {
        $refresh_ttl = $this->jwt->getConfig('refresh_ttl') ?? 60 * 60 * 2; // 单位秒，默认2小时内可以刷新
        if ($jwt instanceof Jwt) {
            $key = $jwt->getHeader('jti');
            $expTime = time() - $jwt->getPayload('exp') - $refresh_ttl; // 黑名单存储时间 = 当前时间 - 绝对过期时间 - 刷新时间
        } else {
            $key = $jwt;
            $expTime = $refresh_ttl; // 黑名单存储时间
        }
        // redis存储黑名单至刷新周期结束后十秒
        $expTime = $expTime > 0 ? $expTime + 10 : 10;
        return $this->cache->set('black_' . $key, time(), $expTime);
    }

    /**
     * 判断令牌是否在黑名单
     * @param Jwt $jwt
     * @return bool
     * @throws InvalidArgumentException
     */
    private function hasBlacklist(Jwt $jwt): bool
    {
        $key = 'black_' . $jwt->getHeader('jti');
        return $this->cache->has($key);
    }

    /**
     * 解析token并验证其有效性
     * @param string|null $token 为NULL时获取当前登录用户的token对象
     * @return Jwt
     * @throws InvalidArgumentException
     */
    public function getTokenParse(?string $token = null): Jwt
    {
        if ($token = $token ?? $this->parseToken()) {
            $jwt = $this->jwt->justParse($token);
            $timestamp = time();
            if ($this->hasBlacklist($jwt)) {
                throw new AuthException('The token is already on the blacklist');
            }
            if (!$jwt->getConfig('single')) {
                $newAge = md5($this->request->getHeader('user-agent')[0] . $jwt->getConfig('secret'));
                if ($jwt->getHeader('age') !== $newAge) {
                    throw new AuthException('Abnormal network environment');
                }
            }
            if ($jwt->getPayload('exp') && $jwt->getPayload('exp') <= $timestamp) {
                throw (new TokenExpiredException('Token expired'))->setJwt($jwt);
            }
            return $jwt;
        }
        throw new AuthException('The token is required.');
    }

    /**
     * 退出登录
     * @param string|null $token
     * @return bool
     * @throws InvalidArgumentException
     */
    public function logout(?string $token = null): bool
    {
        try {
            $jwt = $this->getTokenParse($token);
        } catch (Exception\TokenExpiredException $e) {
            $jwt = $e->getJwt();
        }
        $cache_key = $jwt->getScene() . '_' . $jwt->getPayload('sub');
        $this->cache->delete("auth_$cache_key");
        return $this->addBlacklist($jwt);
    }

    /**
     * 刷新 token，旧 token 会失效.
     * @param string|Jwt|null $token 为null时获取当前登录token
     * @param bool $force 是否强制刷新，无视刷新周期
     * @return string
     * @throws InvalidArgumentException
     */
    public function refresh(string|Jwt|null $token = null, bool $force = false): string
    {
        if (!$token instanceof Jwt) {
            try {
                $jwt = $this->getTokenParse($token);
            } catch (Exception\TokenExpiredException $e) {
                $jwt = $e->getJwt();
            }
        } else {
            $jwt = $token;
        }
        $refresh_ttl = $jwt->getConfig('refresh_ttl') ?? 60 * 60 * 2; // 默认2小时内可以刷新
        $refreshExp = $jwt->getPayload('exp') + $refresh_ttl; // 过期时间加上刷新周期
        $cache_key = $jwt->getScene() . '_' . $jwt->getPayload('sub');
        if (!$force && $refreshExp <= time()) {
            $this->cache->delete("auth_$cache_key");
            throw new AuthException('token expired, refresh is not supported');
        }
        // 由于解析token会校验有效性，所以刷新时从缓存中获取用户信息，不能通过user()方法获取
        $user = $this->cache->get("auth_$cache_key");
        if (is_null($user)) {
            $this->addBlacklist($jwt);
            throw new AuthException('The token is already on the blacklist');
        }
        $newJwt = $this->parseLogin($user, $jwt->getPayload());
        $token = $newJwt->getToken();
        // 存储到当前携程上下文
        Context::set('__auth__:refresh:token', $token);
        // 旧token添加到黑名单
        $this->addBlacklist($jwt);
        return $token;
    }


    /**
     * 根据token获取用户ID
     * @param string|null $token 为空时获取当前登录用户ID
     * @return mixed
     * @throws InvalidArgumentException
     */
    public function id(?string $token = null): mixed
    {
        return $this->getTokenParse($token)->getPayload('sub');
    }

    /**
     * 检查登录|检查token有效性
     * @param string|null $token
     * @throws InvalidArgumentException
     */
    public function check(?string $token = null)
    {
        $this->getTokenParse($token);
    }

    /**
     * 获取用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return UserInterface
     * @throws InvalidArgumentException
     */
    public function user(): UserInterface
    {
        $jwt = $this->getTokenParse();
        $cache_key = $jwt->getScene() . '_' . $jwt->getPayload('sub');
        $user = $this->cache->get("auth_$cache_key");
        if (is_null($user)) {
            $this->addBlacklist($jwt);
            throw new AuthException('The token is already on the blacklist');
        }
        return $user;
    }

    /**
     * 刷新用户信息
     * @param UserInterface $user
     * @return bool
     * @throws InvalidArgumentException
     */
    public function refreshUser(UserInterface $user): bool
    {
        $jwt = $this->getTokenParse();
        $cache_key = $jwt->getScene() . '_' . $user->getId();
        $refresh_ttl = $this->jwt->getConfig('refresh_ttl') ?? 60 * 60 * 2; // 默认2小时内可以刷新
        return $this->cache->set("auth_$cache_key", $user, $jwt->getPayload('exp') + $refresh_ttl);
    }

    /**
     * 是否超级管理员
     * @return bool
     * @throws InvalidArgumentException
     */
    public function isSuperAdmin(): bool
    {
        $jwt = $this->getTokenParse();
        $superAdmin = $jwt->getConfig('super_admin');
        if ($superAdmin) {
            return $jwt->getPayload('sub') == $superAdmin;
        }
        return false;
    }
}
