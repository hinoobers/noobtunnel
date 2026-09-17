<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('noobtunnel_publications', function (Blueprint $table) {
            $table->id();
            $table->unsignedInteger('server_id');
            $table->unsignedInteger('allocation_id');
            $table->unsignedInteger('resource_id');
            $table->string('protocol', 16);
            $table->string('name');
            $table->unsignedInteger('public_port');
            $table->string('domain')->nullable();
            $table->string('public_address')->nullable();
            $table->timestamps();

            $table->unique(['allocation_id', 'protocol'], 'noobtunnel_allocation_protocol_unique');
            $table->unique('resource_id');
            $table->foreign('server_id')->references('id')->on('servers')->cascadeOnDelete();
            $table->foreign('allocation_id')->references('id')->on('allocations')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('noobtunnel_publications');
    }
};
