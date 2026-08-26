# دليل البدء السريع - Laravel Security

## 🚀 في 3 خطوات فقط!

### الخطوة 1: التثبيت

```bash
composer require shammaa/laravel-security
```

### الخطوة 2: إضافة Middleware

في `app/Http/Kernel.php` (Laravel 10) أو `bootstrap/app.php` (Laravel 11):

```php
// Laravel 11
protected $middleware = [
    \Shammaa\LaravelSecurity\Http\Middleware\SecurityMiddleware::class,
];

// Laravel 10
protected $middlewareGroups = [
    'web' => [
        \Shammaa\LaravelSecurity\Http\Middleware\SecurityMiddleware::class,
    ],
];
```

### الخطوة 3: تشغيل Migrations (اختياري - للمراقبة فقط)

```bash
php artisan migrate
```

## ✅ انتهى!

الآن كل طلباتك محمية تلقائياً من:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- File Upload Attacks
- وغيرها...

## 💡 أمثلة سريعة

### تنظيف Input

```php
$clean = security_sanitize($request->input('name'));
```

### فلترة XSS

```php
$safe = security_xss_filter($html);
```

### Rate Limiting

```php
if (!security_rate_limit('api:' . $userId)) {
    return response()->json(['error' => 'Too many requests'], 429);
}
```

## 📖 للمزيد

راجع `README.md` للأمثلة المتقدمة والإعدادات.

