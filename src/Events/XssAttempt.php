<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class XssAttempt
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public string $input,
        public string $pattern,
        public ?string $ip = null,
        public ?string $userAgent = null
    ) {
        $this->ip = $ip ?? request()->ip();
        $this->userAgent = $userAgent ?? request()->userAgent();
    }
}

