<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blocked_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip')->unique();
            $table->text('reason')->nullable();
            $table->boolean('is_blocked')->default(true);
            $table->timestamp('blocked_at')->nullable();
            $table->timestamp('blocked_until')->nullable();
            $table->timestamps();

            $table->index('ip');
            $table->index('is_blocked');
            $table->index('blocked_until');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blocked_ips');
    }
};

