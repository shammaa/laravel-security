<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Services;

use Illuminate\Foundation\Auth\User;
use Shammaa\LaravelSecurity\Events\UnauthorizedAccessAttempt;
use Illuminate\Support\Facades\Event;

class IdorProtectionService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Validate resource access
     */
    public function validateAccess($resource, User $user, string $ownerField = 'user_id'): bool
    {
        if (!isset($this->config['enabled']) || !$this->config['enabled']) {
            return true;
        }

        // Check ownership
        if (isset($this->config['validate_ownership']) && $this->config['validate_ownership']) {
            if (!$this->checkOwnership($resource, $user, $ownerField)) {
                Event::dispatch(new UnauthorizedAccessAttempt($user, $resource, 'ownership'));
                return false;
            }
        }

        // Check permissions
        if (isset($this->config['check_permissions']) && $this->config['check_permissions']) {
            if (!$this->checkPermissions($resource, $user)) {
                Event::dispatch(new UnauthorizedAccessAttempt($user, $resource, 'permissions'));
                return false;
            }
        }

        return true;
    }

    /**
     * Check resource ownership
     */
    protected function checkOwnership($resource, User $user, string $ownerField): bool
    {
        if (is_object($resource)) {
            if (isset($resource->$ownerField)) {
                return $resource->$ownerField === $user->id;
            }
            
            // Check for polymorphic relationships
            if (method_exists($resource, 'user')) {
                $owner = $resource->user;
                return $owner && $owner->id === $user->id;
            }
        }

        if (is_array($resource)) {
            return isset($resource[$ownerField]) && $resource[$ownerField] === $user->id;
        }

        return false;
    }

    /**
     * Check permissions
     */
    protected function checkPermissions($resource, User $user): bool
    {
        // Check if user has permission to access resource
        // This can be extended with policy checks
        if (method_exists($resource, 'canBeAccessedBy')) {
            return $resource->canBeAccessedBy($user);
        }

        // Default: allow if ownership is valid
        return true;
    }

    /**
     * Validate resource ID
     */
    public function validateResourceId($id, array $allowedIds = []): bool
    {
        if (empty($allowedIds)) {
            return true;
        }

        return in_array($id, $allowedIds);
    }

    /**
     * Generate secure resource token
     */
    public function generateResourceToken($resource, User $user): string
    {
        $data = [
            'resource_id' => is_object($resource) ? $resource->id : $resource,
            'user_id' => $user->id,
            'timestamp' => time(),
        ];

        return hash_hmac('sha256', json_encode($data), config('app.key'));
    }

    /**
     * Validate resource token
     */
    public function validateResourceToken(string $token, $resource, User $user): bool
    {
        $expectedToken = $this->generateResourceToken($resource, $user);
        return hash_equals($expectedToken, $token);
    }
}

