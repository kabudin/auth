<?php
declare(strict_types=1);

namespace Bud\Auth;

interface AuthInterface
{
    /**
     * 根据token获取用户ID
     * @param string|null $token 为空时获取当前登录用户ID
     */
    public function id(?string $token = null);

    /**
     * 登录，返回token字符串
     * @param $userId
     * @param array $payload
     * @return string
     */
    public function login($userId, array $payload = []): string;

    /**
     * 该方式登录返回jwt对象，可以结合payload处理一些其他业务逻辑。
     * 例如：payload中添加登录设备类型，登录成功获取 jti token标识，再结合forceExit($jti)来达到强退某个已登录的设备
     * @param $userId
     * @param array $payload
     * @return Jwt
     */
    public function parseLogin($userId, array $payload = []): Jwt;

    /**
     * 根据token标识强制失效某个token
     * @param string $jti token标识payload中获取
     * @return bool
     */
    public function forceExit(string $jti): bool;

    /**
     * 解析token并验证其有效性
     * @param string|null $token 为NULL时获取当前登录用户的token对象
     * @return Jwt
     */
    public function getTokenParse(?string $token = null): Jwt;

    /**
     * 解析当前登录用户的token，不验证签名。
     * 用于场景不明确，但需要获取token信息的情况。
     * 通常在经过一次验证后，再次获取token信息时使用。
     * @return Jwt|null 返回null表示未登录，使用该对象重新生成的token不可再次使用。
     */
    public function justParse(): ?Jwt;

    /**
     * 退出登录
     * @param string|null $token
     * @return bool
     */
    public function logout(?string $token = null): bool;

    /**
     * 刷新 token，旧 token 会失效.
     * @param string|Jwt|null $token 为null时获取当前登录token
     * @param bool $force 是否强制刷新，无视刷新周期
     * @return string
     */
    public function refresh(string|Jwt|null $token = null, bool $force = false): string;

    /**
     * 检查登录|检查token有效性
     * @param string|null $token
     */
    public function check(?string $token = null);

    /**
     * 获取用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return object|null
     */
    public function getUserInfo(): ?object;

    /**
     * 获取当前用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserPermissionCodes(): array;

    /**
     * 获取当前用户角色标识列表，必须是一个由角色标识组成的一维数组
     * 当使用 Roles 注解验证角色权限时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserRoleCodes(): array;


    /**
     * 获取当前用户岗位标识列表，必须是一个由岗位标识组成的一维数组
     * 当使用 Post 注解验证岗位权限时必须正确返回，否则可返回空
     * @return array
     */
    public function getUserPostCodes(): array;

    /**
     * 判断当前用户是否超级管理员
     * @return bool
     */
    public function isSuperAdmin(): bool;
}
