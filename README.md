# Laravel Security Package

Comprehensive security package for Laravel - Automatically protects against all types of security vulnerabilities!

## ⚡ Quick Installation (3 Steps Only!)

```bash
# 1. Install the package
composer require shammaa/laravel-security

# 2. Publish configuration (optional - everything works automatically)
php artisan vendor:publish --tag=laravel-security-config

# 3. Run migrations (for monitoring and logging)
php artisan migrate
```

## 🚀 Usage - Super Easy!

### Method 1: 100% Automatic (Easiest)

Just add one middleware in `app/Http/Kernel.php` or `bootstrap/app.php`:

```php
// Laravel 11+
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\Shammaa\LaravelSecurity\Http\Middleware\SecurityMiddleware::class);
});

// Or Laravel 10
protected $middlewareGroups = [
    'web' => [
        \Shammaa\LaravelSecurity\Http\Middleware\SecurityMiddleware::class,
    ],
];
```

**That's it!** Now all your requests are automatically protected from:
- ✅ **SQL Injection** - Detect and prevent SQL injection attacks
- ✅ **XSS (Cross-Site Scripting)** - Filter malicious scripts and HTML
- ✅ **Command Injection** - Block dangerous system commands
- ✅ **Path Traversal** - Prevent directory traversal attacks (../)
- ✅ **CSRF (Cross-Site Request Forgery)** - Enhanced CSRF protection with token rotation
- ✅ **XXE (XML External Entity)** - Protect against XML external entity attacks
- ✅ **SSRF (Server-Side Request Forgery)** - Block internal network access
- ✅ **IDOR (Insecure Direct Object Reference)** - Validate resource ownership
- ✅ **File Upload Attacks** - Secure file validation with MIME type checking
- ✅ **Brute Force Attacks** - Account lockout after failed attempts
- ✅ **Rate Limiting** - Prevent API abuse and DDoS
- ✅ **Security Headers** - Automatic CSP, HSTS, X-Frame-Options, etc.
- ✅ **Input Sanitization** - Clean all user inputs automatically
- ✅ **IP Blocking** - Auto-block malicious IPs
- ✅ **Security Monitoring** - Log and track all security threats

### Method 2: Using Helper Functions (Very Simple)

```php
// Sanitize any input
$clean = security_sanitize($request->input('name'));

// Filter XSS
$safe = security_xss_filter($html);

// Rate Limiting
if (!security_rate_limit('api:' . $userId)) {
    return response()->json(['error' => 'Too many requests'], 429);
}
```

### Method 3: Using Facade (Simplest)

```php
use Shammaa\LaravelSecurity\Facades\Security;

// Sanitize
$clean = Security::sanitize($input);

// Filter XSS
$safe = Security::xssFilter($html);

// Validate file
if (Security::validateFile($file)) {
    $path = Security::storeFile($file);
}

// Check password strength
$result = Security::checkPassword($password);
if (!$result['valid']) {
    // $result['errors'] contains the errors
}

// Check if account is locked
if (Security::isLocked($email)) {
    return back()->withErrors(['email' => 'Account locked']);
}

// Record failed login attempt
Security::recordFailedLogin($email);

// Clear failed attempts on success
Security::clearFailedLogins($email);
```

## 📋 Complete Features List

### Core Security Protections
- ✅ **Automatic Protection** - Just add one middleware and everything works!
- ✅ **SQL Injection Protection** - Detect and prevent SQL injection attacks with pattern matching
- ✅ **XSS Protection** - Filter malicious scripts, iframes, and JavaScript code
- ✅ **Command Injection Protection** - Block dangerous system commands (exec, system, etc.)
- ✅ **Path Traversal Protection** - Prevent directory traversal attacks (../, ..\\)
- ✅ **CSRF Protection** - Enhanced CSRF protection with token rotation and double submit cookie
- ✅ **XXE Protection** - Protect against XML External Entity attacks
- ✅ **SSRF Protection** - Block Server-Side Request Forgery to internal networks
- ✅ **IDOR Protection** - Validate resource ownership and prevent insecure direct object references

### File & Upload Security
- ✅ **File Upload Security** - Secure file validation with MIME type and extension checking
- ✅ **Magic Bytes Validation** - Verify file content matches extension
- ✅ **Executable File Blocking** - Automatically block dangerous file types
- ✅ **Secure File Storage** - Automatic file renaming and secure directory storage

### Authentication & Authorization
- ✅ **Brute Force Protection** - Account lockout after failed login attempts
- ✅ **Password Strength Validation** - Enforce strong password policies
- ✅ **Session Security** - Enhanced session protection
- ✅ **Authorization Policies** - Ready-to-use security policies

### Rate Limiting & DDoS Protection
- ✅ **Rate Limiting** - Advanced rate limiting per IP, user, or route
- ✅ **IP Whitelist/Blacklist** - Manage trusted and blocked IPs
- ✅ **Exponential Backoff** - Smart retry logic

### Security Headers
- ✅ **Content Security Policy (CSP)** - Prevent XSS and data injection
- ✅ **Strict Transport Security (HSTS)** - Force HTTPS connections
- ✅ **X-Frame-Options** - Prevent clickjacking attacks
- ✅ **X-Content-Type-Options** - Prevent MIME type sniffing
- ✅ **Referrer-Policy** - Control referrer information
- ✅ **Permissions-Policy** - Control browser features

### Monitoring & Logging
- ✅ **Security Monitoring** - Real-time threat detection and logging
- ✅ **Security Events** - Track all security-related events
- ✅ **IP Blocking** - Automatic IP blocking for repeated threats
- ✅ **Security Reports** - Generate comprehensive security reports
- ✅ **Threat Statistics** - View security statistics and analytics

### Input Validation
- ✅ **Input Sanitization** - Clean all user inputs automatically
- ✅ **HTML Tag Stripping** - Remove dangerous HTML tags
- ✅ **SQL Keyword Filtering** - Remove SQL keywords from inputs
- ✅ **Data Type Validation** - Validate input data types

### Additional Features
- ✅ **Helper Functions** - Easy-to-use helper functions
- ✅ **Facade Support** - Clean API with Facade pattern
- ✅ **Artisan Commands** - Security scanning, reporting, and management
- ✅ **Event System** - Listen to security events
- ✅ **Policy System** - Extensible security policies
- ✅ **Validator Classes** - Reusable validators for all security checks

## ⚙️ Configuration (Optional)

Everything works automatically! But if you want to customize, edit `config/security.php`:

```php
return [
    // Enable/disable protection
    'sql_injection' => [
        'enabled' => true,  // true = enabled, false = disabled
        'block_on_detect' => true,  // Auto-block on detection
    ],
    
    'xss' => [
        'enabled' => true,
        'filter_input' => true,  // Filter inputs
    ],
    
    // Or use .env
    // SECURITY_SQL_INJECTION_ENABLED=true
    // SECURITY_XSS_ENABLED=true
];
```

### Whitelisting Routes for Admin Panels & WYSIWYG Editors

If you're using admin panels with rich text editors (like CKEditor, TinyMCE) or DataTables, you may need to whitelist certain routes to bypass strict security checks.

#### Option 1: Using Environment Variables (Recommended)

Add these to your `.env` file:

```env
# Whitelist routes for input sanitization (comma-separated)
SECURITY_INPUT_WHITELIST_ROUTES=admin/*,dashboard/posts/create,dashboard/posts/edit

# Whitelist specific parameters that should not be sanitized
SECURITY_INPUT_WHITELIST_PARAMS=content,description,body,html,editor_content

# Whitelist routes for XSS filtering (for WYSIWYG editors)
SECURITY_XSS_WHITELIST_ROUTES=admin/*,dashboard/*

# Whitelist routes for security headers (for admin panels)
SECURITY_HEADERS_WHITELIST_ROUTES=admin/*,dashboard/*
```

#### Option 2: Using Config File

Edit `config/security.php`:

```php
'input' =&gt; [
    'whitelist_routes' =&gt; ['admin/*', 'dashboard/posts/*'],
    'whitelist_parameters' =&gt; ['content', 'description', 'body', 'html'],
],

'xss' =&gt; [
    'whitelist_routes' =&gt; ['admin/*', 'dashboard/*'],
],

'headers' =&gt; [
    'whitelist_routes' =&gt; ['admin/*', 'dashboard/*'],
],
```

#### Example: CKEditor Setup

```env
# For CKEditor to work properly
SECURITY_INPUT_WHITELIST_PARAMS=content,description,article_body
SECURITY_XSS_WHITELIST_ROUTES=admin/articles/*,admin/pages/*
SECURITY_HEADERS_WHITELIST_ROUTES=admin/*

# Make CSP more permissive for admin panel
SECURITY_HEADER_CSP="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.ckeditor.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
```

#### Example: DataTables Setup

```env
# For DataTables with server-side processing
SECURITY_HEADERS_WHITELIST_ROUTES=admin/datatables/*,api/datatables/*
```

**Important Notes:**
- Whitelist only admin routes that you trust
- Use specific route patterns instead of wildcards when possible
- Always validate user permissions before allowing access to whitelisted routes
- Consider using middleware groups for better organization


## 🛠️ Commands

### Security Scan

```bash
php artisan security:scan
php artisan security:scan --fix  # Attempt to fix issues
```

### Generate Security Report

```bash
php artisan security:report
php artisan security:report --days=60 --format=table
```

### Unblock IP

```bash
php artisan security:unblock 192.168.1.1
```

### Clean Security Logs

```bash
php artisan security:clean --days=30
php artisan security:clean --days=30 --force  # Without confirmation
```

## 💡 Practical Examples

### Example 1: File Upload Security (Super Easy!)

```php
// In Controller
public function upload(Request $request)
{
    $file = $request->file('document');
    
    // Simple way - Helper Function
    if (!security_validate_file($file)) {
        return back()->withErrors(['file' => 'File not allowed']);
    }
    
    // Secure storage
    $path = security_store_file($file);
    
    // Or use Facade
    if (Security::validateFile($file)) {
        $path = Security::storeFile($file);
    }
    
    return response()->json(['path' => $path]);
}
```

### Example 2: Rate Limiting for API

```php
// In Controller or Middleware
public function apiEndpoint(Request $request)
{
    $userId = auth()->id();
    
    // Rate limit: 100 requests per minute
    if (!Security::rateLimit("api:{$userId}", 100, 1)) {
        return response()->json([
            'error' => 'Too many requests'
        ], 429);
    }
    
    // Rest of the code...
}
```

### Example 3: Brute Force Protection (Super Easy!)

```php
// In LoginController
public function login(Request $request)
{
    $email = $request->email;
    
    // Simple way - Helper Functions
    if (security_is_locked($email)) {
        return back()->withErrors(['email' => 'Account locked. Try again later.']);
    }
    
    if (!Auth::attempt($request->only('email', 'password'))) {
        // Record failed attempt
        security_record_failed_login($email);
        return back()->withErrors(['email' => 'Invalid credentials']);
    }
    
    // Success - clear failed attempts
    security_clear_failed_logins($email);
    
    return redirect('/dashboard');
    
    // Or use Facade
    // if (Security::isLocked($email)) { ... }
    // Security::recordFailedLogin($email);
    // Security::clearFailedLogins($email);
}
```

### Example 4: Manual Input Sanitization

```php
// Sanitize any input
$name = security_sanitize($request->input('name'));
$email = security_sanitize($request->input('email'));

// Or use Facade
$name = Security::sanitize($request->input('name'));
```

### Example 5: Filter Output from XSS

```php
// In Blade
{!! Security::xssFilter($user->bio) !!}

// Or Helper
{!! security_xss_filter($user->bio) !!}
```

## 📚 More Information

### Policies

The package includes ready-to-use policies that you can customize:
- `SecurityPolicy` - General security operations
- `FileUploadPolicy` - File upload permissions
- `ApiSecurityPolicy` - API access control
- `AdminSecurityPolicy` - Admin operations

### Events

The package fires events when threats are detected:
- `SecurityThreatDetected` - When any threat is detected
- `SqlInjectionAttempt` - SQL injection attempt
- `XssAttempt` - XSS attempt
- `BruteForceAttempt` - Brute force attack
- `UnauthorizedAccessAttempt` - Unauthorized access attempt

You can listen to these events:

```php
use Shammaa\LaravelSecurity\Events\SecurityThreatDetected;

Event::listen(SecurityThreatDetected::class, function ($event) {
    // Send email, notification, etc...
    Mail::to('admin@example.com')->send(new SecurityAlert($event));
});
```

## 🎯 Summary

**Basic Usage:**
1. Install the package
2. Add one middleware
3. Done! Everything works automatically

**For Advanced Users:**
- Use Helper Functions or Facade
- Customize settings in `config/security.php`
- Use Commands for monitoring and reports

## 📄 License

MIT

## 👤 Author

Shadi Shammaa
