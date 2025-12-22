<?php

namespace Shammaa\LaravelSecurity\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Shammaa\LaravelSecurity\LaravelSecurityServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            LaravelSecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Setup environment
    }
}

