<?php

declare(strict_types=1);

namespace Shammaa\LaravelSecurity;

use Illuminate\Support\ServiceProvider;
use Shammaa\LaravelSecurity\Services\InputSanitizerService;
use Shammaa\LaravelSecurity\Services\SqlInjectionDetector;
use Shammaa\LaravelSecurity\Services\XssProtectionService;
use Shammaa\LaravelSecurity\Services\CsrfProtectionService;
use Shammaa\LaravelSecurity\Services\FileUploadSecurityService;
use Shammaa\LaravelSecurity\Services\RateLimitingService;
use Shammaa\LaravelSecurity\Services\SecurityHeadersService;
use Shammaa\LaravelSecurity\Services\AuthenticationSecurityService;
use Shammaa\LaravelSecurity\Services\AuthorizationSecurityService;
use Shammaa\LaravelSecurity\Services\CommandInjectionDetector;
use Shammaa\LaravelSecurity\Services\PathTraversalDetector;
use Shammaa\LaravelSecurity\Services\XxeProtectionService;
use Shammaa\LaravelSecurity\Services\SsrfProtectionService;
use Shammaa\LaravelSecurity\Services\IdorProtectionService;
use Shammaa\LaravelSecurity\Services\SecurityMonitoringService;
use Shammaa\LaravelSecurity\Services\SecurityReportService;
use Shammaa\LaravelSecurity\Commands\SecurityScanCommand;
use Shammaa\LaravelSecurity\Commands\GenerateSecurityReportCommand;
use Shammaa\LaravelSecurity\Commands\UnblockIpCommand;
use Shammaa\LaravelSecurity\Commands\CleanSecurityLogsCommand;

class LaravelSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/security.php',
            'security'
        );

        // Register Services
        $this->app->singleton(InputSanitizerService::class, fn ($app) => new InputSanitizerService(config('security.input')));
        $this->app->singleton(SqlInjectionDetector::class, fn ($app) => new SqlInjectionDetector(config('security.sql_injection')));
        $this->app->singleton(XssProtectionService::class, fn ($app) => new XssProtectionService(config('security.xss')));
        $this->app->singleton(CsrfProtectionService::class, fn ($app) => new CsrfProtectionService(config('security.csrf')));
        $this->app->singleton(FileUploadSecurityService::class, fn ($app) => new FileUploadSecurityService(config('security.file_upload')));
        $this->app->singleton(RateLimitingService::class, fn ($app) => new RateLimitingService(config('security.rate_limiting')));
        $this->app->singleton(SecurityHeadersService::class, fn ($app) => new SecurityHeadersService(config('security.headers')));
        $this->app->singleton(AuthenticationSecurityService::class, fn ($app) => new AuthenticationSecurityService(config('security.authentication')));
        $this->app->singleton(AuthorizationSecurityService::class);
        $this->app->singleton(CommandInjectionDetector::class, fn ($app) => new CommandInjectionDetector(config('security.command_injection')));
        $this->app->singleton(PathTraversalDetector::class, fn ($app) => new PathTraversalDetector(config('security.path_traversal')));
        $this->app->singleton(XxeProtectionService::class, fn ($app) => new XxeProtectionService(config('security.xxe')));
        $this->app->singleton(SsrfProtectionService::class, fn ($app) => new SsrfProtectionService(config('security.ssrf')));
        $this->app->singleton(IdorProtectionService::class, fn ($app) => new IdorProtectionService(config('security.idor')));
        $this->app->singleton(SecurityMonitoringService::class, fn ($app) => new SecurityMonitoringService(config('security.monitoring')));
        $this->app->singleton(SecurityReportService::class);

        // Register main Security service
        $this->app->singleton('security', function ($app) {
            return new Services\SecurityService(
                $app->make(InputSanitizerService::class),
                $app->make(SqlInjectionDetector::class),
                $app->make(XssProtectionService::class),
                $app->make(CsrfProtectionService::class),
                $app->make(FileUploadSecurityService::class),
                $app->make(RateLimitingService::class),
                $app->make(SecurityHeadersService::class),
                $app->make(AuthenticationSecurityService::class),
                $app->make(AuthorizationSecurityService::class),
                $app->make(CommandInjectionDetector::class),
                $app->make(PathTraversalDetector::class),
                $app->make(XxeProtectionService::class),
                $app->make(SsrfProtectionService::class),
                $app->make(IdorProtectionService::class),
                $app->make(SecurityMonitoringService::class),
                $app->make(SecurityReportService::class),
                config('security')
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/security.php' => config_path('security.php'),
        ], 'laravel-security-config');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'laravel-security');

        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityScanCommand::class,
                GenerateSecurityReportCommand::class,
                UnblockIpCommand::class,
                CleanSecurityLogsCommand::class,
            ]);
        }

        // Register middleware
        $this->app['router']->aliasMiddleware('security', Http\Middleware\SecurityMiddleware::class);
        $this->app['router']->aliasMiddleware('security.input', Http\Middleware\InputValidationMiddleware::class);
        $this->app['router']->aliasMiddleware('security.sql', Http\Middleware\SqlInjectionMiddleware::class);
        $this->app['router']->aliasMiddleware('security.xss', Http\Middleware\XssProtectionMiddleware::class);
        $this->app['router']->aliasMiddleware('security.rate', Http\Middleware\RateLimitingMiddleware::class);
        $this->app['router']->aliasMiddleware('security.headers', Http\Middleware\SecurityHeadersMiddleware::class);
        $this->app['router']->aliasMiddleware('security.file', Http\Middleware\FileUploadSecurityMiddleware::class);

        // Register Event Listeners
        $this->app['events']->listen(
            Events\SecurityThreatDetected::class,
            Listeners\LogSecurityThreat::class
        );

        $this->app['events']->listen(
            Events\SecurityThreatDetected::class,
            Listeners\BlockIpAddress::class
        );

        $this->app['events']->listen(
            Events\SecurityThreatDetected::class,
            Listeners\SendSecurityAlert::class
        );

        $this->app['events']->listen(
            Events\SecurityThreatDetected::class,
            Listeners\RateLimitUser::class
        );
    }
}

