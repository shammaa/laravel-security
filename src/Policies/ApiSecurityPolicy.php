<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Policies;

use Illuminate\Foundation\Auth\User;

class ApiSecurityPolicy
{
    /**
     * Determine if user can access API
     */
    public function accessApi(User $user): bool
    {
        // Add your authorization logic here
        return true;
    }

    /**
     * Determine if user can perform rate-limited actions
     */
    public function performRateLimitedAction(User $user): bool
    {
        // Add your authorization logic here
        return true;
    }
}

