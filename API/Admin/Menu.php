<?php

namespace Service\API\Admin;

use DB;

class Menu
{
    // 获取用户拥有的权限列表（原始数据）
    public static function getMenuRaw($user, $columns = ['*'])
    {
        if ($user->id == 1) {
            return DB::table('admin_role_permissions as aup')
                ->where('aup.rule', 'LIKE', '%index')
                ->orWhere('aup.parent_id', '=', 0)
                ->orderBy('aup.id')
                ->get($columns);
        }

        return DB::table('admin_users as au')
            ->join('admin_user_has_role as aur', 'au.id', '=', 'aur.user_id')
            ->join('admin_role_has_permission as aupr', 'aur.role_id', '=', 'aupr.role_id')
            ->join('admin_role_permissions as aup', 'aupr.permission_id', '=', 'aup.id')
            ->where('au.id', '=', $user->id)
            ->where(function ($query) {
                $query->where('aup.rule', 'LIKE', '%index')
                    ->orWhere('aup.parent_id', '=', 0);
            })
            ->orderBy('aup.id')
            ->get($columns);
    }

    // 获取用户拥有的权限列表
    public static function getMenu($user, $columns = ['*'])
    {
        $menus = self::getMenuRaw($user, $columns);
        $result = array(
                'tree'    => [],
                'subtree' => [],
        );

        foreach ($menus as $menu) {
            if ($menu->parent_id == 0) {
                $result['tree'][$menu->id] = $menu;
                $result['subtree'][$menu->id] = [];
                $menu->active = false;
            } else {
                $menu->rule = str_replace('/index', '', $menu->rule);
                $result['subtree'][$menu->parent_id][$menu->id] = $menu;

                $pathinfo = request()->get('__pathinfo__');
                $pathinfo_arr = explode('/', $pathinfo);
                if ($pathinfo_arr[0] == $menu->rule) {
                    $menu->active = true;
                    $result['tree'][$menu->parent_id]->active = true;
                } else {
                    $menu->active = false;
                }
            }
        }

        return $result;
    }
}
