<?php

declare(strict_types=1);

if (!function_exists('security_sanitize')) {
    /**
     * تنظيف Input - أسهل طريقة
     * 
     * @param mixed $input
     * @return mixed
     */
    function security_sanitize($input)
    {
        return app('security')->sanitize($input);
    }
}

if (!function_exists('security_clean')) {
    /**
     * تنظيف String من الأحرف الخطيرة
     */
    function security_clean(string $input): string
    {
        return app('security')->getInputSanitizer()->clean($input);
    }
}

if (!function_exists('security_detect_sql_injection')) {
    /**
     * كشف SQL Injection
     */
    function security_detect_sql_injection(string $input): bool
    {
        return app('security')->detectSqlInjection($input);
    }
}

if (!function_exists('security_xss_filter')) {
    /**
     * فلترة XSS - أسهل طريقة
     */
    function security_xss_filter(string $html): string
    {
        return app('security')->xssFilter($html);
    }
}

if (!function_exists('security_rate_limit')) {
    /**
     * Rate Limiting - أسهل طريقة
     * 
     * @param string $key - مفتاح فريد (مثلاً: 'api:user:123')
     * @param int|null $maxAttempts - عدد المحاولات (افتراضي: 60)
     * @param int|null $decayMinutes - المدة بالدقائق (افتراضي: 1)
     * @return bool - true إذا مسموح، false إذا تجاوز الحد
     */
    function security_rate_limit(string $key, int $maxAttempts = null, int $decayMinutes = null): bool
    {
        return app('security')->rateLimit($key, $maxAttempts, $decayMinutes);
    }
}

if (!function_exists('security_validate_file')) {
    /**
     * فحص ملف مرفوع - أسهل طريقة
     * 
     * @param \Illuminate\Http\UploadedFile $file
     * @return bool
     */
    function security_validate_file($file): bool
    {
        return app('security')->getFileUploadSecurity()->validate($file);
    }
}

if (!function_exists('security_store_file')) {
    /**
     * حفظ ملف بشكل آمن - أسهل طريقة
     * 
     * @param \Illuminate\Http\UploadedFile $file
     * @param string|null $path
     * @return string - مسار الملف المحفوظ
     */
    function security_store_file($file, string $path = null): string
    {
        return app('security')->getFileUploadSecurity()->storeSecurely($file, $path);
    }
}

if (!function_exists('security_check_password')) {
    /**
     * فحص قوة كلمة المرور - أسهل طريقة
     * 
     * @param string $password
     * @return array ['valid' => bool, 'errors' => array]
     */
    function security_check_password(string $password): array
    {
        return app('security')->getAuthenticationSecurity()->validatePasswordStrength($password);
    }
}

if (!function_exists('security_is_locked')) {
    /**
     * فحص إذا الحساب محظور - أسهل طريقة
     * 
     * @param string $identifier - البريد الإلكتروني أو المعرف
     * @return bool
     */
    function security_is_locked(string $identifier): bool
    {
        return app('security')->getAuthenticationSecurity()->isLocked($identifier);
    }
}

if (!function_exists('security_record_failed_login')) {
    /**
     * تسجيل محاولة تسجيل دخول فاشلة - أسهل طريقة
     * 
     * @param string $identifier
     * @return void
     */
    function security_record_failed_login(string $identifier): void
    {
        app('security')->getAuthenticationSecurity()->recordFailedAttempt($identifier);
    }
}

if (!function_exists('security_clear_failed_logins')) {
    /**
     * مسح محاولات تسجيل الدخول الفاشلة - أسهل طريقة
     * 
     * @param string $identifier
     * @return void
     */
    function security_clear_failed_logins(string $identifier): void
    {
        app('security')->getAuthenticationSecurity()->clearFailedAttempts($identifier);
    }
}

