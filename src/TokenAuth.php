<?php
declare(strict_types=1);

namespace Bud\Auth;

use Bud\Auth\Exception\TokenExpiredException;
use Hyperf\Context\ApplicationContext;
use Hyperf\Context\Context;
use Hyperf\Coroutine\Coroutine;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Redis\Redis;
use Hyperf\Redis\RedisFactory;
use Hyperf\Stringable\Str;
use Bud\Auth\Exception\AuthException;
use Psr\Container\ContainerInterface;
use function Hyperf\Support\make;

class TokenAuth implements AuthInterface
{
    protected Jwt $jwt;

    protected Redis $redis;

    protected ContainerInterface $container;

    protected RequestInterface $request;

    protected string $headerName;

    public function __construct(string $scene = 'admin')
    {
        $this->container = ApplicationContext::getContainer();
        $this->jwt = new Jwt($scene);
        $this->headerName = $this->jwt->getConfig('header_name') ?? 'Authorization';
        $redis_pool = $this->jwt->getConfig('redis_pool') ?? 'default';
        $this->redis = $this->container->get(RedisFactory::class)->get($redis_pool);
        $this->request = $this->container->get(RequestInterface::class);
    }

    /**
     * 从请求中解析token
     * @return mixed
     */
    public function parseToken(): mixed
    {
        // 首先判断上下文中是否存在刷新token，如果存在则使用新token
        if (Context::has('__auth__:refresh:token'))
            return Context::get('__auth__:refresh:token');
        // 然后判断上下文中是否存在登录token，如果存在则使用登录token
        if (Context::has('__auth__:login:token'))
            return Context::get('__auth__:login:token')->getToken;
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
     * @param $userId
     * @param array $payload
     * @return string
     */
    public function login($userId, array $payload = []): string
    {
        return $this->parseLogin($userId, $payload)->getToken();
    }

    /**
     * 登录，返回jwt对象
     * @param $userId
     * @param array $payload
     * @return Jwt
     */
    public function parseLogin($userId, array $payload = []): Jwt
    {
        $timestamp = time();
        $secret = $this->jwt->getConfig('secret');
        $ttl = $this->jwt->getConfig('ttl') ?? 60 * 60 * 24;
        $age = md5($this->request->getHeader('user-agent')[0] . $this->jwt->getConfig('secret'));
        $jwt = $this->jwt->setPayload($payload)
            ->addPayload('sub', $userId) // 设置所属用户
            ->addPayload('iat', $timestamp) // 签发时间
            ->addPayload('exp', $timestamp + $ttl) // 过期时间
            ->addPayload('iss', $this->request->getHeader('host')[0]) // 设置签发者
            ->addHeaders('age', $age);
        $jti = hash('md5', base64_encode(json_encode([$this->jwt->getPayload(), $this->jwt->getHeader()])) . $secret);
        $jwt->addHeaders('jti', $jti);
        return $jwt;
    }

    /**
     * 根据token标识强制失效某个token
     * @param string $jti token标识payload中获取
     * @return bool
     */
    public function forceExit(string $jti): bool
    {
        return $this->addBlacklist($jti);
    }

    /**
     * 将token添加到黑名单
     * @param Jwt|string $jwt jwt对象或者jti标识
     * @return bool
     */
    protected function addBlacklist(Jwt|string $jwt): bool
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
        return $this->redis->set('black_' . $key, time(), $expTime);
    }

    /**
     * 判断令牌是否在黑名单
     * @param Jwt $jwt
     * @return bool|int
     */
    protected function hasBlacklist(Jwt $jwt): bool|int
    {
        $key = 'black_' . $jwt->getHeader('jti');
        return $this->redis->exists($key);
    }

    /**
     * 解析token并验证其有效性
     * @param string|null $token 为NULL时获取当前登录用户的token对象
     * @return Jwt
     */
    public function getTokenParse(?string $token = null): Jwt
    {
        if ($token = $token ?? $this->parseToken()) {
            $jwt = $this->jwt->justParse($token);
            $timestamp = time();
            if ($this->hasBlacklist($jwt)) {
                throw new AuthException('The token is already on the blacklist');
            }
//            $newAge = md5($this->request->getHeader('user-agent')[0] . $jwt->getConfig('secret'));
//            if ($jwt->getHeader('age') !== $newAge) {
//                throw new AuthException('Abnormal network environment');
//            }
            if ($jwt->getPayload('exp') && $jwt->getPayload('exp') <= $timestamp) {
                throw (new TokenExpiredException('Token expired'))->setJwt($jwt);
            }
            return $jwt;
        }
        throw new AuthException('The token is required.');
    }

    /**
     * 解析当前登录用户的token，不验证签名。
     * 用于场景不明确，但需要获取token信息的情况。
     * 通常在经过一次验证后，再次获取token信息时使用。
     * @return Jwt|null 返回null表示未登录，使用该对象重新生成的token不可再次使用。
     */
    public function justParse(): ?Jwt
    {
        if ($token = $this->parseToken()) {
            return $this->jwt->justParse($token, false);
        }
        return null;
    }

    /**
     * 退出登录
     * @param string|null $token
     * @return bool
     */
    public function logout(?string $token = null): bool
    {
        try {
            $jwt = $this->getTokenParse($token);
        } catch (Exception\TokenExpiredException $e) {
            $jwt = $e->getJwt();
        }
        return $this->addBlacklist($jwt);
    }

    /**
     * 刷新 token，旧 token 会失效.
     * @param string|Jwt|null $token 为null时获取当前登录token
     * @param bool $force 是否强制刷新，无视刷新周期
     * @return string
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
        if (!$force && $refreshExp <= time()) {
            throw new AuthException('token expired, refresh is not supported');
        }
        $key = md5(json_encode($jwt->getPayload()));
        $lockKey = 'lock:' . $key;
        $retryCount = $jwt->getConfig('retry') ?? 2; // 默认重试2次
        $retryInterval = $jwt->getConfig('retry_time') ?? 1; // 默认重试间隔1秒
        $startTime = time();
        while (time() - $startTime < $retryCount * $retryInterval) { // 重试总时长
            if ($this->redis->set($lockKey, 1, ['nx', 'ex' => 5])) { // 获取到锁权限，则刷新token
                try {
                    $token = $this->parseLogin($jwt->getPayload('sub'), $jwt->getPayload())->getToken();
                    // 存储到当前携程上下文
                    Context::set('__auth__:refresh:token', $token);
                    // 旧token添加到黑名单
                    $this->addBlacklist($jwt);
                    return $token;
                } finally {
                    $this->redis->del($lockKey); // 释放锁
                }
            }
            // 退避机制
            usleep(rand(100000, 200000)); // 随机等待100ms到200ms，减少并发冲突
            Coroutine::sleep($retryInterval); // 等待重试间隔时间再重试
        }
        throw new AuthException('Failed to refresh token due to lock timeout');
    }


    /**
     * 根据token获取用户ID
     * @param string|null $token 为空时获取当前登录用户ID
     */
    public function id(?string $token = null)
    {
        return $this->getTokenParse($token)->getPayload('sub');
    }

    /**
     * 检查登录|检查token有效性
     * @param string|null $token
     */
    public function check(?string $token = null)
    {
        $this->getTokenParse($token);
    }

    /**
     * 获取用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return object|null
     */
    public function getUserInfo(): ?object
    {
        return $this->user()?->getUserInfo($this->id());
    }

    /**
     * 获取用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserPermissionCodes(): array
    {
        return $this->user()?->getPermissionCodes($this->id()) ?? [];
    }

    /**
     * 获取用户角色标识列表，必须是一个由角色标识组成的一维数组
     * 当使用 Roles 注解验证角色权限时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserRoleCodes(): array
    {
        return $this->user()?->getRoleCodes($this->id()) ?? [];
    }

    /**
     * 获取用户岗位标识列表，必须是一个由岗位标识组成的一维数组
     * 当使用 Post 注解验证岗位权限时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserPostCodes(): array
    {
        return $this->user()?->getPostCodes($this->id()) ?? [];
    }

    /**
     * 是否超级管理员
     * @return bool
     */
    public function isSuperAdmin(): bool
    {
        return $this->user()?->isSuperAdmin($this->id()) ?? false;
    }

    /**
     * 获取当前登录用户模型
     * @return ?UserInterface
     */
    protected function user(): ?UserInterface
    {
        $service = $this->jwt->getConfig('service');
        if (empty($service)) return null;
        try {
            $model = new \ReflectionClass($service);
        } catch (\ReflectionException $e) {
            throw new AuthException('Invalid user model configuration:' . $e->getMessage());
        }
        if (!$model->implementsInterface(UserInterface::class))
            throw new AuthException('The user model must implement the \Bud\Auth\UserInterface interface',);
        return make($service);
    }
}
