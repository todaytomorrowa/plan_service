<?php

namespace Service\Models;

use Illuminate\Database\Eloquent\Model;

class Monitor extends Model
{
    protected $table='monitor';
    /**
     * 该模型是否被自动维护时间戳
     *
     * @var bool
     */
    public $timestamps = false;
}
