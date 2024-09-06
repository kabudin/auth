<?php
declare(strict_types=1);

namespace Bud\Auth;

interface UserInterface
{
    /**
     * 获取用户主键ID
     */
    public function getId();

    /**
     * 必须是一个由操作权限标识组成的一维数组
     * 当使用 Permission 注解鉴权时必须正确返回，否则可返回空
     * @return array
     */
    public function getPermissionCodes(): array;

    /**
     * 必须是一个由角色标识组成的一维数组
     * 当使用 Roles 注解验证角色权限时必须正确返回，否则可返回空
     * @return array
     */
    public function getRoleCodes(): array;
}
