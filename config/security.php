<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Input Sanitization
    |--------------------------------------------------------------------------
    */
    'input' => [
        'sanitize' => env('SECURITY_INPUT_SANITIZE', true),
        'strip_tags' => env('SECURITY_STRIP_TAGS', true),
        'html_entities' => env('SECURITY_HTML_ENTITIES', true),
        'sql_keywords' => env('SECURITY_SQL_KEYWORDS', true),
        'allowed_tags' => ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'div', 'span'],
        
        // Whitelist: Routes that should bypass input sanitization (e.g., WYSIWYG editors)
        'whitelist_routes' => explode(',', env('SECURITY_INPUT_WHITELIST_ROUTES', '')),
        
        // Whitelist: Request parameters that should not be sanitized (e.g., 'content', 'description')
        'whitelist_parameters' => explode(',', env('SECURITY_INPUT_WHITELIST_PARAMS', 'content,description,body,html')),
    ],

    /*
    |--------------------------------------------------------------------------
    | SQL Injection Protection
    |--------------------------------------------------------------------------
    */
    'sql_injection' => [
        'enabled' => env('SECURITY_SQL_INJECTION_ENABLED', true),
        'detect_patterns' => env('SECURITY_SQL_DETECT_PATTERNS', true),
        'block_on_detect' => env('SECURITY_SQL_BLOCK_ON_DETECT', true),
        'log_attempts' => env('SECURITY_SQL_LOG_ATTEMPTS', true),
        'patterns' => [
            '/(\bUNION\b.*\bSELECT\b)/i',
            '/(\bSELECT\b.*\bFROM\b)/i',
            '/(\bINSERT\b.*\bINTO\b.*\bVALUES\b)/i',
            '/(\bDELETE\b.*\bFROM\b)/i',
            '/(\bUPDATE\b.*\bSET\b)/i',
            '/(\bDROP\b.*\bTABLE\b)/i',
            '/(\bEXEC\b|\bEXECUTE\b)/i',
            '/(\bOR\b\s+(?:\d+|[\'"][^\'"]*[\'"])\s*=\s*(?:\d+|[\'"][^\'"]*[\'"]))/i',
            '/(\bAND\b\s+(?:\d+|[\'"][^\'"]*[\'"])\s*=\s*(?:\d+|[\'"][^\'"]*[\'"]))/i',
            '/(\b--\b|\b#\b)/',
            '/(\b\/\*.*\*\/\b)/',
            '/(\b1\s*=\s*1\b)/i',
            '/(\b1\s*=\s*0\b)/i',
            '/(\bCHAR\s*\(|CHR\s*\()/i',
            '/(\bCONCAT\s*\()/i',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | XSS Protection
    |--------------------------------------------------------------------------
    */
    'xss' => [
        'enabled' => env('SECURITY_XSS_ENABLED', true),
        'filter_input' => env('SECURITY_XSS_FILTER_INPUT', true),
        'filter_output' => env('SECURITY_XSS_FILTER_OUTPUT', true),
        'csp_enabled' => env('SECURITY_XSS_CSP_ENABLED', true),
        'patterns' => [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/mi',
            '/javascript:/i',
            '/\bon\w+\s*=/i',
            '/<img[^>]+src[^>]*=.*javascript:/i',
            '/<link[^>]+href[^>]*=.*javascript:/i',
        ],
        
        // Whitelist: Routes that should bypass XSS filtering (e.g., admin content editors)
        'whitelist_routes' => explode(',', env('SECURITY_XSS_WHITELIST_ROUTES', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | CSRF Protection
    |--------------------------------------------------------------------------
    */
    'csrf' => [
        'enabled' => env('SECURITY_CSRF_ENABLED', true),
        'token_rotation' => env('SECURITY_CSRF_TOKEN_ROTATION', true),
        'double_submit_cookie' => env('SECURITY_CSRF_DOUBLE_SUBMIT', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | File Upload Security
    |--------------------------------------------------------------------------
    */
    'file_upload' => [
        'enabled' => env('SECURITY_FILE_UPLOAD_ENABLED', true),
        'max_size' => env('SECURITY_FILE_MAX_SIZE', 10240), // KB
        'allowed_extensions' => explode(',', env('SECURITY_FILE_ALLOWED_EXTENSIONS', 'jpg,jpeg,png,gif,pdf,doc,docx')),
        'allowed_mime_types' => explode(',', env('SECURITY_FILE_ALLOWED_MIME_TYPES', 'image/jpeg,image/png,image/gif,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document')),
        'scan_content' => env('SECURITY_FILE_SCAN_CONTENT', true),
        'rename_files' => env('SECURITY_FILE_RENAME', true),
        'secure_directory' => env('SECURITY_FILE_SECURE_DIR', storage_path('app/uploads')),
        'block_executable' => env('SECURITY_FILE_BLOCK_EXECUTABLE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    */
    'rate_limiting' => [
        'enabled' => env('SECURITY_RATE_LIMITING_ENABLED', true),
        'max_attempts' => env('SECURITY_RATE_MAX_ATTEMPTS', 60),
        'decay_minutes' => env('SECURITY_RATE_DECAY_MINUTES', 1),
        'block_on_exceed' => env('SECURITY_RATE_BLOCK_ON_EXCEED', true),
        'whitelist_ips' => explode(',', env('SECURITY_RATE_WHITELIST_IPS', '')),
        'blacklist_ips' => explode(',', env('SECURITY_RATE_BLACKLIST_IPS', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Headers
    |--------------------------------------------------------------------------
    */
    'headers' => [
        'enabled' => env('SECURITY_HEADERS_ENABLED', true),
        'csp' => env('SECURITY_HEADER_CSP', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"),
        'x_frame_options' => env('SECURITY_HEADER_X_FRAME_OPTIONS', 'DENY'),
        'x_content_type_options' => env('SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        'x_xss_protection' => env('SECURITY_HEADER_X_XSS_PROTECTION', '1; mode=block'),
        'strict_transport_security' => env('SECURITY_HEADER_HSTS', 'max-age=31536000; includeSubDomains'),
        'referrer_policy' => env('SECURITY_HEADER_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'permissions_policy' => env('SECURITY_HEADER_PERMISSIONS_POLICY', 'geolocation=(), microphone=(), camera=()'),
        // Whitelist: Routes that should bypass strict security headers (e.g., admin panels)
        'whitelist_routes' => explode(',', env('SECURITY_HEADERS_WHITELIST_ROUTES', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Security
    |--------------------------------------------------------------------------
    */
    'authentication' => [
        'enabled' => env('SECURITY_AUTH_ENABLED', true),
        'brute_force_protection' => env('SECURITY_AUTH_BRUTE_FORCE', true),
        'max_login_attempts' => env('SECURITY_AUTH_MAX_ATTEMPTS', 5),
        'lockout_duration' => env('SECURITY_AUTH_LOCKOUT_DURATION', 900), // seconds
        'password_strength' => env('SECURITY_AUTH_PASSWORD_STRENGTH', true),
        'min_password_length' => env('SECURITY_AUTH_MIN_PASSWORD_LENGTH', 8),
        'require_mixed_case' => env('SECURITY_AUTH_REQUIRE_MIXED_CASE', true),
        'require_numbers' => env('SECURITY_AUTH_REQUIRE_NUMBERS', true),
        'require_symbols' => env('SECURITY_AUTH_REQUIRE_SYMBOLS', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Command Injection Protection
    |--------------------------------------------------------------------------
    */
    'command_injection' => [
        'enabled' => env('SECURITY_CMD_INJECTION_ENABLED', true),
        'detect_patterns' => env('SECURITY_CMD_DETECT_PATTERNS', true),
        'block_on_detect' => env('SECURITY_CMD_BLOCK_ON_DETECT', true),
        'patterns' => [
            '/[;&|`$(){}]/',
            '/\b(exec|system|shell_exec|passthru|proc_open|popen)\s*\(/i',
            '/\b(eval|assert)\s*\(/i',
            '/\b(base64_decode|gzinflate|str_rot13)\s*\(/i',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Path Traversal Protection
    |--------------------------------------------------------------------------
    */
    'path_traversal' => [
        'enabled' => env('SECURITY_PATH_TRAVERSAL_ENABLED', true),
        'detect_patterns' => env('SECURITY_PATH_DETECT_PATTERNS', true),
        'block_on_detect' => env('SECURITY_PATH_BLOCK_ON_DETECT', true),
        'patterns' => [
            '/\.\.\//',
            '/\.\.\\\\/',
            '/\.\.%2F/',
            '/\.\.%5C/',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | XXE Protection
    |--------------------------------------------------------------------------
    */
    'xxe' => [
        'enabled' => env('SECURITY_XXE_ENABLED', true),
        'disable_external_entities' => env('SECURITY_XXE_DISABLE_EXTERNAL', true),
        'disable_entity_loader' => env('SECURITY_XXE_DISABLE_LOADER', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | SSRF Protection
    |--------------------------------------------------------------------------
    */
    'ssrf' => [
        'enabled' => env('SECURITY_SSRF_ENABLED', true),
        'block_internal_ips' => env('SECURITY_SSRF_BLOCK_INTERNAL', true),
        'block_private_ips' => env('SECURITY_SSRF_BLOCK_PRIVATE', true),
        'allowed_domains' => explode(',', env('SECURITY_SSRF_ALLOWED_DOMAINS', '')),
        'blocked_domains' => explode(',', env('SECURITY_SSRF_BLOCKED_DOMAINS', '')),
    ],

    /*
    |--------------------------------------------------------------------------
    | IDOR Protection
    |--------------------------------------------------------------------------
    */
    'idor' => [
        'enabled' => env('SECURITY_IDOR_ENABLED', true),
        'validate_ownership' => env('SECURITY_IDOR_VALIDATE_OWNERSHIP', true),
        'check_permissions' => env('SECURITY_IDOR_CHECK_PERMISSIONS', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Monitoring
    |--------------------------------------------------------------------------
    */
    'monitoring' => [
        'enabled' => env('SECURITY_MONITORING_ENABLED', false),
        'log_all_requests' => env('SECURITY_MONITORING_LOG_ALL', false),
        'log_threats' => env('SECURITY_MONITORING_LOG_THREATS', true),
        'alert_on_threat' => env('SECURITY_MONITORING_ALERT_ON_THREAT', false),
        'alert_email' => env('SECURITY_MONITORING_ALERT_EMAIL', null),
        'log_channel' => env('SECURITY_MONITORING_LOG_CHANNEL', 'daily'),
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Blocking
    |--------------------------------------------------------------------------
    */
    'ip_blocking' => [
        'enabled' => env('SECURITY_IP_BLOCKING_ENABLED', true),
        'auto_block' => env('SECURITY_IP_AUTO_BLOCK', true),
        'block_after_attempts' => env('SECURITY_IP_BLOCK_AFTER_ATTEMPTS', 5),
        'block_duration' => env('SECURITY_IP_BLOCK_DURATION', 3600), // seconds
        'permanent_block' => env('SECURITY_IP_PERMANENT_BLOCK', false),
        'whitelist_ips' => explode(',', env('SECURITY_IP_WHITELIST', '127.0.0.1,::1')),
    ],
];

