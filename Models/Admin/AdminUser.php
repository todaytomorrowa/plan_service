<?php

namespace Service\Models\Admin;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class AdminUser extends Authenticatable
{
    use Notifiable;

    protected $table='admin_users';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = ['usernick', 'username', 'password'];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = ['password', 'remember_token'];


    /**
     * 用户角色
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles()
    {
        return $this->belongsToMany(
            AdminRole::class,
            'admin_user_has_role',
            'user_id',
            'role_id'
        );
    }

    /**
     * 判断用户是否具有某个角色
     * @param $role
     * @return bool
     */
    public function hasRole($role)
    {
        if (is_string($role)) {
            return $this->roles->contains('name', $role);
        }

        return !!$role->intersect($this->roles)->count();
    }

    /**
     * 判断用户是否具有某权限
     * @param $permission
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->hasRole($permission->roles);
    }

    /**
     * 给用户分配角色
     * @param $role
     * @return \Illuminate\Database\Eloquent\Model
     */
    public function assignRole($role)
    {
        return $this->roles()->save($role);
    }

    /**
     * 角色整体添加与修改
     * @param array $role_id
     * @return bool
     */
    public function giveRoleTo(array $role_id)
    {
        $this->roles()->detach();
        $roles = AdminRole::whereIn('id', $role_id)->get();
        foreach ($roles as $v) {
            $this->assignRole($v);
        }
        return true;
    }
}
