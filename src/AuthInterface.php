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
     * 初始化一个JWT场景
     * @param string $scene
     * @return TokenAuth
     */
    public function scene(string $scene = 'admin'): TokenAuth;

    /**
     * 强制退出某个用户
     * @param string $scene
     * @param UserInterface $user
     * @return bool
     */
    public function forceExit(string $scene, UserInterface $user): bool;

    /**
     * 解析token并验证其有效性
     * @param string|null $token 为NULL时获取当前登录用户的token对象
     * @return Jwt
     */
    public function getTokenParse(?string $token = null): Jwt;

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
     * @return UserInterface
     */
    public function user(): UserInterface;

    /**
     * 刷新用户信息
     * @param UserInterface $user
     * @return bool
     */
    public function refreshUser(UserInterface $user): bool;

    /**
     * 判断当前用户是否超级管理员
     * @return bool
     */
    public function isSuperAdmin(): bool;
}
