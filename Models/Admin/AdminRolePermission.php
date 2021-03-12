<?php

namespace Service\Models\Admin;

use Illuminate\Database\Eloquent\Model;

class AdminRolePermission extends Model
{
    protected $table = 'admin_role_permissions';

    /**
     * 该模型是否被自动维护时间戳
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles()
    {
        return $this->belongsToMany(
            AdminRole::class,
            'admin_role_has_permission',
            'permission_id',
            'role_id'
        );
    }
}
