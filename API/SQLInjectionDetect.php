<?php
namespace Service\API;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Service\Models\UserBehaviorLog;
use Service\Models\IpFirewall;
use Service\API\Log;

class SQLInjectionDetect
{
    use Log;

    private $get_filter = "\\b(and|or)\\b.+?(>|<|=|in|like)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(CREATE|REPLACE|DROP).+?(FUNCTION|TRIGGER)";
    private $post_filter = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(CREATE|REPLACE|DROP).+?(FUNCTION|TRIGGER)";
    private $cookie_filter = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*\\/?script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(CREATE|REPLACE|DROP).+?(FUNCTION|TRIGGER)";


    private $black_words = [
        ['select', 'from'],
        ['delete', 'from'],
        ['update', 'set'],
        ['insert', 'into'],
        ['replace', 'into'],
        ['information_schema'],
        ['drop', 'database'],
        ['drop', 'table'],
        ['truncate', 'table'],
        ['show', 'databases'],
        ['show', 'tables'],
        ['union', 'select'],
        ['create', 'function'],
        ['replace', 'function'],
        ['alter', 'function'],
        ['drop', 'function'],
        ['language', 'plpgsql'],
        ['create', 'trigger'],
        ['alter', 'trigger'],
        ['drop', 'trigger'],
        ['create', 'view'],
        ['select', '(', ')'],
        ['as', 'return'],
        ['$', 'begin', 'end'],
        ['execute', 'procedure'],
        ['message_deletes'],
        ['eval', '(', ')'],
        ['base64_'],
        ['file_put_contents'],
        ['cmd='],
        ['php', '@'],
        ['php', 'post'],
        ['serialize'],
        ['unserialize'],
    ];

    //不进行 filter 检查的路径
    private $backend_forbid_filter_paths = [
        'frontmenu/create',
        'frontmenu/edit',
        'frontmenu/editdata',
        'config',
    ];
    private $frontend_forbid_filter_paths = [

    ];

    private $response_status = 500;
    private $response_message = 'System error.';
    private $is_backend = 0; // 0前台、1后台
    private $injection2block_minutes = 10; //多少分钟内
    private $injection2block_times = 5; //注入多少次数，自动加入登录黑名单
    private $is_block_ip = false; //是否封锁IP
    private $counter_cache_key_pre = 'SQLInjectionIP:'; //注入IP统计缓存key前缀
    private $counter_cache_type = 'redis'; //缓存类型，redis、apc
    private $is_save_to_blacklist = true; //是否保存到 登录IP黑名单

    public function check($is_backend=0)
    {
        $this->is_backend = $is_backend;

        $ip = request()->ip();
        $all_data = request()->all();
        $all_cookies = request()->cookie();
        $path = request()->path();
        if(!$this->_check_ip_rule($ip)) {
            $this->_add_log($all_data, $is_backend, '来路IP规则错误');
            $this->_increment_ip_counter($ip);
            return false;
        }
        if($this->_check_is_block_ip($ip)) {
            $this->_add_log($all_data, $is_backend, '自动封锁IP');
            $this->_increment_ip_counter($ip);
            return false;
        }
        $use_filter = true;
        if($is_backend && in_array($path, $this->backend_forbid_filter_paths)) {
            $use_filter = false;
        }
        if($is_backend == 0 && in_array($path, $this->frontend_forbid_filter_paths)) {
            $use_filter = false;
        }
        foreach ($all_data as $key=>$value) {
            $value = $this->_array2string($value);
            if($use_filter) {
                if (preg_match("/" . $this->get_filter . "/is", $value)) {
                    $this->_add_log($all_data, $is_backend, 'get_filter');
                    $this->_increment_ip_counter($ip);
                    return false;
                }
                if (preg_match("/" . $this->post_filter . "/is", $value)) {
                    $this->_add_log($all_data, $is_backend, 'post_filter');
                    $this->_increment_ip_counter($ip);
                    return false;
                }
            }
            if(empty($is_backend)) {
                $value = strtolower($value);
                foreach ($this->black_words as $item_array) {
                    $word_check_array = [];
                    foreach ($item_array as $word) {
                        if(strpos($value, strtolower($word)) !== false) {
                            $word_check_array[] = $word;
                        }
                    }
                    if(count($item_array) == count($word_check_array)) {
                        $this->_add_log($all_data, $is_backend, implode(',', $word_check_array));
                        $this->_increment_ip_counter($ip);
                        return false;
                    }
                }
            }
        }
        foreach ($all_cookies as $key=>$value) {
            $value = $this->_array2string($value);
            if (preg_match("/" . $this->cookie_filter . "/is", $value)) {
                $this->_add_log($all_cookies, $is_backend, 'cookie_filter');
                $this->_increment_ip_counter($ip);
                return false;
            }
            $value = strtolower($value);
            foreach ($this->black_words as $item_array) {
                $word_check_array = [];
                foreach ($item_array as $word) {
                    if(strpos($value, strtolower($word)) !== false) {
                        $word_check_array[] = $word;
                    }
                }
                if(count($item_array) == count($word_check_array)) {
                    $this->_add_log($all_cookies, $is_backend, 'cookies:'.implode(',', $word_check_array));
                    $this->_increment_ip_counter($ip);
                    return false;
                }
            }
        }
        return true;
    }

    public function response()
    {
        //强制用户退出登录
        if($this->is_block_ip) {
            auth()->guard()->logout();
            request()->session()->invalidate();
        }

        if(request()->ajax()) {
            return response()->json([
                'status' => -2,
                'code' => $this->response_status,
                'msg' => $this->response_message,
                'data' => []
            ])->setStatusCode($this->response_status);
        } else {
            return response($this->response_message, $this->response_status);
        }
    }

    private function _array2string($array)
    {
        $string = '';
        if(is_array($array)) {
            foreach ($array as $key=>$val) {
                if(is_array($val)) {
                    $string .= $this->_array2string($val);
                } else {
                    $string .= $val;
                }
            }
        } else {
            $string .= $array;
        }
        return $string;
    }

    private function _add_log($data, $is_backend=0, $words='')
    {
        $type_name = empty($is_backend) ? 'Frontend' : 'Backend';
        $description = $type_name . ' ';
        $description .= 'IP：' . request()->ip(). "    \n";
        $description .= '路径：' . request()->path(). "    \n";
        $description .= '方式：'. request()->method(). "    \n";
        $description .= '拦截：'. $words. "    \n";
        $description .= '数据：'. (is_array($data) ? json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : $data);

        $user_id = auth()->id() ?? 0;

        $this->_initLogger($type_name, 'SQLInjectionDetect');
        $this->_log($description."\nuser_id={$user_id} \n");

        return UserBehaviorLog::insert([
            'user_id' => $user_id,
            'db_user' => env('DB_USERNAME'),
            'level'   =>  1,
            'action'  => 'SQL 注入',
            'description'=>$description,
        ]);
    }

    private function _increment_ip_counter($ip)
    {
        $key = $this->counter_cache_key_pre.md5($ip);
        $counter = Cache::store($this->counter_cache_type)->get($key, 0);
        $counter += 1;
        Cache::store($this->counter_cache_type)->put($key, $counter, $this->injection2block_minutes);
        if($counter >= $this->injection2block_times) {
            $this->is_block_ip = true;
            if($this->is_save_to_blacklist && $counter == $this->injection2block_times) {
                $black_ip = IpFirewall::where('type', 'user')
                    ->where('ip', '>>=', DB::raw("inet '$ip'"))
                    ->first(['ip']);
                if(empty($black_ip)) {
                    $row = new IpFirewall();
                    $row->type = 'user';
                    $row->ip = $ip;
                    $row->remark = 'SQL注入多次，自动加入封锁';
                    $row->admin = 'system';
                    $row->save();
                }
            }
        }
    }

    private function _check_is_block_ip($ip)
    {
        if($this->is_block_ip) {
            return true;
        }
        $key = $this->counter_cache_key_pre.md5($ip);
        $counter = Cache::store($this->counter_cache_type)->get($key, 0);
        if($counter >= $this->injection2block_times) {
            $this->is_block_ip = true;
            return true;
        }
    }

    private function _check_ip_rule($ip)
    {
        if (!empty($ip) && (preg_match('`^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d\/]{1,5}$`', $ip) || preg_match('/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?(\/\d+)?\s*$/', $ip))) {
            return true;
        } else {
            $this->is_block_ip = true;
            return false;
        }
    }
}
