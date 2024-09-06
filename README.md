# auth

> 适配 hyperf 框架的JWT-AUTH权限控制，该组件参考了组件 96qbhy/hyperf-auth 仅保留了jwt算法。更为精简的配置。增加了Permission操作鉴权注解以及Roles角色鉴权注解，token刷新周期内的自动刷新

## 安装

```shell
composer require bud/auth
```

发布配置

```bash
php bin/hyperf.php vendor:publish bud/auth
```

```php
<?php
declare(strict_types=1);

use Bud\Auth\Manager\EncryptAdapters as Encrypter;
use function Hyperf\Support\env;

return [
    'scenes' => [
        'admin' => [
            // redis连接池
            'redis_pool' => 'default',
            // token秘钥，根据加密类的实现该配置可以为数组。默认仅实现了对称加密，所以默认为字符串
            'secret' => env('TOKEN_SECRET', 'dgfjkdhsjghkdfjhshgjsssjh;dhf'),
            // 请求头token使用的字段
            'header_name' => env('TOKEN_HEADER_NAME', 'Authorization'),
            // token 生命周期，单位秒，默认一天
            'ttl' => (int)env('TOKEN_TTL', 60 * 60 * 24),
            // 允许过期多久以内的 token 自动刷新，单位秒，默认一周
            'refresh_ttl' => (int)env('TOKEN_REFRESH_TTL', 60 * 60 * 24 * 7),
            // 是否自动刷新，仅在使用Auth注解下生效
            'auto_refresh' => true,
            // 默认使用的加密类,alg算法标识|完整类名
            'encrypter' => Encrypter\PasswordHashEncrypter::class,
            // 可选加密类。加密类必须实现 \Bud\Auth\Manager\Encrypter 接口
            'drivers' => [
                Encrypter\PasswordHashEncrypter::alg() => Encrypter\PasswordHashEncrypter::class,
                Encrypter\CryptEncrypter::alg() => Encrypter\CryptEncrypter::class,
                Encrypter\SHA1Encrypter::alg() => Encrypter\SHA1Encrypter::class,
                Encrypter\Md5Encrypter::alg() => Encrypter\Md5Encrypter::class,
            ],
        ],
    ]
];
```

## 使用方法

```php
<?php
declare(strict_types=1);

namespace App\Controller;

use Hyperf\Di\Annotation\Inject;
use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\GetMapping;
use Hyperf\HttpServer\Annotation\PostMapping;
use Hyperf\HttpServer\Annotation\DeleteMapping;
use Bud\Auth\Annotation\Auth;
use Bud\Auth\Annotation\Permission;
use Bud\Auth\Annotation\Roles;
use Bud\Auth\AuthInterface;

#[Controller]
class IndexController extends AbstractController
{
    #[Inject]
    protected AuthInterface $auth;

    /**
     * 登录
     * @return array
     */
    #[GetMapping(path:"/login")]
    public function login()
    {
        /** @var User $user */
        $user = User::query()->firstOrCreate(['name' => 'test', 'avatar' => 'avatar']);
        return [
            'token' => $this->auth->scene('admin')->login($user), // 常规登录返回token字符串
            //  'token' => $this->auth->scene('admin')->parseLogin($user,['agent' => $this->request->getHeader('user-agent')[0]])->token(), // 自定义登录返回jwt对象
            //  'token' => auth('admin')->login($user), // 助手函数公共方法登录
        ];
    }

    /**
     * 退出当前登录用户
     */
    #[GetMapping(path:"/logout"),Auth]
    public function logout()
    {
        $this->auth->scene('admin')->logout();
        // auth('admin')->logout();
        return 'logout ok';
    }

    /**
     * 使用 Permission 注解确保当前登录用户必需拥有user或者user:list权限才能获取列表
     * @return string
     */
    #[GetMapping(path:"/user"),Permission(codes: "user,user:list", where: "OR")]
    public function list(int $id)
    {
        return User::query()->get();
    }

    /**
     * 使用 Permission 注解确保当前登录用户必需拥有 user:add 权限
     * @return string
     */
    #[PostMapping(path:"/user"),Permission(codes: "user:add", title: "添加用户")]
    public function add()
    {
        return User::create(['name' => 'test', 'avatar' => 'avatar']);
    }

    /**
     * 使用 Auth 注解可以保证该方法必须是已登录用户才能访问
     * @return string
     */
    #[GetMapping(path:"/info/{id}"),Auth]
    public function info(int $id)
    {
        return User::find($id);
    }

    /**
     * 使用 Roles 注解确保必须是超级管理员才能删除用户
     * @return string
     */
    #[DeleteMapping(path:"/user"),Roles("superAdmin")]
    public function delete()
    {
        return User::create(['name' => 'test', 'avatar' => 'avatar']);
    }
}
```
## 使用该组件User模型必须实现 \Bud\Auth\UserInterface 接口
## Token自动刷新

#### 1、只有在使用Auth注解进行登录拦截并且开启自动刷新时才会触发token自动刷新，
#### 2、当token刷新后会在响应头中携带刷新后的token。前端可以检测响应头中是否存在token，如果存在则应该更新本地缓存的token用于下一次请求
#### 3、需要重新登录状态码为401。权限相关为403

## 异常

#### 1、Token过期会触发 \Bud\Auth\Exception\TokenExpiredException 状态码为402。
#### 2、登录失效 \Bud\Auth\Exception\AuthException 状态码为401。
#### 3、权限相关 \Bud\Auth\Exception\PermissionException 状态码为403。
