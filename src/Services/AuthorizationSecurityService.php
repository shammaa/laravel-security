<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Gate;

class AuthorizationSecurityService
{
    /**
     * Check if user can perform action
     */
    public function can(User $user, string $ability, $arguments = null): bool
    {
        return Gate::forUser($user)->allows($ability, $arguments);
    }

    /**
     * Check if user cannot perform action
     */
    public function cannot(User $user, string $ability, $arguments = null): bool
    {
        return Gate::forUser($user)->denies($ability, $arguments);
    }

    /**
     * Authorize action
     */
    public function authorize(User $user, string $ability, $arguments = null): void
    {
        Gate::forUser($user)->authorize($ability, $arguments);
    }

    /**
     * Check resource ownership
     */
    public function checkOwnership($resource, User $user, string $ownerField = 'user_id'): bool
    {
        if (is_object($resource) && isset($resource->$ownerField)) {
            return $resource->$ownerField === $user->id;
        }

        if (is_array($resource) && isset($resource[$ownerField])) {
            return $resource[$ownerField] === $user->id;
        }

        return false;
    }

    /**
     * Validate resource access
     */
    public function validateResourceAccess($resource, User $user, string $ability = 'access'): bool
    {
        // Check ownership first
        if (!$this->checkOwnership($resource, $user)) {
            return false;
        }

        // Check policy if exists
        if (Gate::has($ability)) {
            return Gate::forUser($user)->allows($ability, $resource);
        }

        return true;
    }
}

