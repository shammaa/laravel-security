<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Events;

use Illuminate\Foundation\Auth\User;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UnauthorizedAccessAttempt
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public User $user,
        public $resource,
        public string $reason,
        public ?string $ip = null,
        public ?string $userAgent = null
    ) {
        $this->ip = $ip ?? request()->ip();
        $this->userAgent = $userAgent ?? request()->userAgent();
    }
}

