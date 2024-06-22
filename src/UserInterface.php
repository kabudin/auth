<?php
declare(strict_types=1);

namespace Bud\Auth;

interface UserInterface
{
    /**
     * 获取用户详情
     * @param $userId
     * @return object|null
     */
    public function getUserInfo($userId): ?object;

    /**
     * 根据当前用户ID获取用户权限标识列表，必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @param $userId
     * @return array
     */
    public function getPermissionCodes($userId): array;

    /**
     * 根据当前用户ID获取用户角色标识列表，必须是一个由角色标识组成的一维数组
     * 当使用 Roles 注解验证角色权限时必须正确返回，否则可返回空
     * @param $userId
     * @return array
     */
    public function getRoleCodes($userId): array;

    /**
     * 根据当前用户ID获取用户岗位标识列表，必须是一个由岗位标识组成的一维数组
     * 当使用 Post 注解验证岗位权限时必须正确返回，否则可返回空
     * @param $userId
     * @return array
     */
    public function getPostCodes($userId): array;

    /**
     * 根据当前用户ID判断是否超级管理员
     * @param $userId
     * @return bool
     */
    public function isSuperAdmin($userId): bool;
}
