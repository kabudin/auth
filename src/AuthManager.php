<?php
declare(strict_types=1);

namespace Bud\Auth;

use function Hyperf\Support\make;

class AuthManager
{
    public function scene(string $scene = 'admin'): AuthInterface
    {
        return make(TokenAuth::class, compact('scene'));
    }
}
