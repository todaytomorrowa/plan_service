<?php
use \Illuminate\Support\Facades\Redis;

if (!defined('STDIN')) {
    define('STDIN', fopen('php://stdin', 'r'));
}
if (!defined('STDOUT')) {
    define('STDOUT', fopen('php://stdout', 'w'));
}

function sql_injection_detect($data, $filter)
{
    if (is_array($data)) {
        foreach ($data as $value) {
            if (sql_injection_detect($value, $filter)) {
                return true;
            }
        }
    } else {
        if (preg_match("/" . $filter . "/is", $data) == 1) {
            return true;
        }
    }

    return false;
}

function get_config($key, $default = '')
{
    if (empty($key)) {
        return false;
    }

    $value = Cache::store('apc')->remember(
        "Redis::{$key}",
        1 / 30, // 缓存 2 秒，这样不需要每次请求 Redis
        function () use ($key) {
            try {
                return Redis::hget('sysConfig', $key);
            } catch (\Exception $e) {
                return false;
            }
        }
    );

    return $value === null ? $default : $value;
}

function get_config_many($keys_array)
{
    if (empty($keys_array)) {
        return false;
    }
    if (is_string($keys_array)) {
        $keys_array = array_map('trim', explode(',', $keys_array));
    }
    $values = Cache::store('apc')->remember(
        "Redis::many_".md5(implode('', $keys_array)),
        1 / 30, // 缓存 2 秒，这样不需要每次请求 Redis
        function () use ($keys_array) {
            try {
                $result = Redis::hmget('sysConfig', $keys_array);
                $values = [];
                foreach ($keys_array as $k => $key) {
                    $values[$key] = $result[$k];
                }
                return $values;
            } catch (\Exception $e) {
                return false;
            }
        }
    );
    return $values;
}

function number_format2(float $number, int $decimals = 0, string $dec_point = '.', string $thousands_sep = ', ')
{
    return number_format($number, $decimals, $dec_point, $thousands_sep);
}

function get_client_types()
{
    return [0 => "Unknown", 1 => "WEB", 2 => "IOS", 3 => "Android", 4 => "挂机", 5 => 'WAP'];
}

function get_mode($mode = null, $key = '')
{
    $modes = [
        1 => [
            'id' => 1,
            'name' => "二元",
            'cost' => 2,
            'rate' => 1
        ],
        2 => [
            'id' => 2,
            'name' => "二角",
            'cost' => 0.2,
            'rate' => 0.1
        ],
        3 => [
            'id' => 3,
            'name' => "二分",
            'cost' => 0.02,
            'rate' => 0.01
        ],
        4 => [
            'id' => 4,
            'name' => "二厘",
            'cost' => 0.002,
            'rate' => 0.001
        ],

        5 => [
            'id' => 5,
            'name' => "一元",
            'cost' => 1,
            'rate' => 0.5
        ],
        6 => [
            'id' => 6,
            'name' => "一角",
            'cost' => 0.1,
            'rate' => 0.05
        ],
        7 => [
            'id' => 7,
            'name' => "一分",
            'cost' => 0.01,
            'rate' => 0.005
        ],
        8 => [
            'id' => 8,
            'name' => "一厘",
            'cost' => 0.001,
            'rate' => 0.0005
        ],
        9 => [
            'id' => 9,
            'name' => "双面",
            'cost' => 1,
            'rate' => 1
        ],
    ];
    if ($mode === null) {
        return $modes;
    }
    if (empty($key)) {
        return $modes[$mode];
    }
    return $modes[$mode][$key];
}

function get_user_type()
{
    return [0 => "非正式用户", 1 => "正式用户"];
}

function get_prize_status()
{
    return [0 => '未判断',1=> '已中奖', 2=> '未中奖'];
}

function get_project_cancel_status()
{
    return [0 => '正常', 1=> '用户撤单', 2=> '公司撤单'];
}

function get_task_status()
{
    return [0 => '进行中',1=> '已取消', 2=> '已完成'];
}

function get_task_detail_status()
{
    return [0 => '进行中',1=> '已完成', 2=> '已取消'];
}

function get_dividend_status()
{
    return [1 => '已发放',2=> '发放中', 3=> '上级审核', 4=> '管理员审核', 5=> '已取消', 6=> '不符合条件',7=>'非结算日'];
}

/**
 * ID 加密
 */
function id_encode($id)
{
    $private_key = 1952463873;

    $id = (string) $id;

    $length = strlen($id);
    $result = '';

    $a = 0;
    $b = $private_key % 33;
    for ($i = 0; $i < $length; $i++) {
        $v = (int) $id{$i};
        $a += $v;
        $b *= $v + 1;
    }

    $m = $a % 9;
    $n = ($a + $b) % 9;
    $key = (int) (($m + $n) / 2);

    $result .= chr(ord($m) + 17 + $private_key % 13);
    for ($i = 0; $i < $length; $i++) {
        $result .= chr(ord($id{$i}) + 17 + ($key + ($i * 13 + $key) * $private_key) % 16);
    }

    $result .= chr(ord($n) + 17 + $private_key % 16);
    return $result;
}

/**
 * ID 解密
 */
function id_decode($data)
{
    $private_key = 1952463873;

    $length = strlen($data);

    if ($length <= 2) {
        return '';
    }

    $result = '';

    $key = (int) (((int) chr(ord($data{0}) - $private_key % 13 - 17) + (int) chr(ord($data{$length - 1}) - $private_key % 16 - 17)) / 2);

    $length -= 1;
    for ($i = 1; $i < $length; $i++) {
        $result .= chr(ord($data{$i}) - 17 - ($key + $private_key * (($i - 1 ) * 13 + $key)) % 16);
    }

    if ($result === (string) ((int) $result)) {
        return $result;
    }

    return '';
}

function ssl_encrypt($string, $key)
{
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-CBC");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext_raw = openssl_encrypt($string, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
    $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = true);
    return base64_encode($iv.$hmac.$ciphertext_raw);
}

function ssl_decrypt($string, $key)
{
    $c = base64_decode($string);
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-CBC");
    $iv = substr($c, 0, $ivlen);
    $hmac = substr($c, $ivlen, $sha2len = 32);

    if ($hmac === false) {
        return '';
    }

    $ciphertext_raw = substr($c, $ivlen + $sha2len);
    $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = true);

    if (hash_equals($hmac, $calcmac)) {
        return openssl_decrypt($ciphertext_raw, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
    }

    return '';
}


/**
 * 将一个字符串部分字符用$re替代隐藏
 *
 * //隐藏手机号中间4位
 * hide_str('18600005940', 3, 4); //186****5940
 * 只保留姓名里的最后一个字，常见与ATM，网银等
 * hide_str('谢世亮', 0, -1); //**亮
 * 隐藏邮箱部分内容，常见网站帐号，如支付宝等
 * list($name, $domain) = explode('@', '979137@qq.com');
 * hide_str($name, 1, -1) . '@' . hide_str($domain, 0, 2); // 9****7@**.com
 *
 * @param string    $string   待处理的字符串
 * @param int       $start    规定在字符串的何处开始，
 *                            正数 - 在字符串的指定位置开始
 *                            负数 - 在从字符串结尾的指定位置开始
 *                            0 - 在字符串中的第一个字符处开始
 * @param int       $length   可选。规定要隐藏的字符串长度。默认是直到字符串的结尾。
 *                            正数 - 从 start 参数所在的位置隐藏
 *                            负数 - 从字符串末端隐藏
 * @param string    $re       替代符
 * @return string   处理后的字符串
 */
function hide_str($string, $start = 0, $length = 0, $re = '*')
{
    if (empty($string)) {
        return false;
    }

    //如果是超管，并且不再CLI下，不隐藏
    if (!app()->runningInConsole() && auth()->id() === 1) {
        return $string;
    }

    $strarr = array();
    $mb_strlen = mb_strlen($string);
    while ($mb_strlen) {//循环把字符串变为数组
        $strarr[] = mb_substr($string, 0, 1, 'utf-8');
        $string = mb_substr($string, 1, $mb_strlen, 'utf-8');
        $mb_strlen = mb_strlen($string);
    }
    $strlen = count($strarr);
    $begin  = $start >= 0 ? $start : ($strlen - abs($start));
    $end    = $last   = $strlen - 1;
    if ($length > 0) {
        $end  = $begin + $length - 1;
    } elseif ($length < 0) {
        $end -= abs($length);
    }
    for ($i=$begin; $i<=$end; $i++) {
        $strarr[$i] = $re;
    }

    return implode('', $strarr);
}

/**
 * 生成随机字符
 * @param string $type 类型
 * @param int $len 长度
 * @return int|string
 */
function random_string($type = 'alnum', $len = 8)
{
    switch ($type) {
        case 'basic':
            return mt_rand();
            break;
        case 'alnum':
        case 'numeric':
        case 'nozero':
        case 'alpha':
            switch ($type) {
                case 'alpha':
                    $pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    break;
                case 'alnum':
                    $pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    break;
                case 'numeric':
                    $pool = '0123456789';
                    break;
                case 'nozero':
                    $pool = '123456789';
                    break;
            }

            $str = '';
            $max = strlen($pool) - 1;
            for ($i = 0; $i < $len; $i++) {
                $str .= substr($pool, mt_rand(0, $max), 1);
            }
            return $str;
            break;
        case 'unique':
        case 'md5':
            return md5(uniqid(mt_rand()));
            break;
    }
}

/**
 * 不四舍五入取小数点后几位
 * @param $num
 * @param $len
 * @return Float
 */
function round_down($num, $precision = 4)
{
    $fig = pow(10, $precision);
    return floor(($num + 0.0000001) * $fig) / $fig;  //  加上 0.0000001，以处理特殊情况精度问题，比如：$num = 20 * (0.95 + 0.038) * 0.5
}


/**
 * 获得请求的来源ip
 * @return string
 */
function getRequestIP()
{
    return request()->ip();
}

/**
 * 检查开奖号码是否正确
 * @param $lottery_type
 * @param $code
 * @return bool|false|int
 */
function check_lottery_draw($lottery_type, $codes)
{
    $result = false;
    switch (strtolower($lottery_type)) {
        case 'ssc':
            $result = preg_match('/^[\d]{5}$/', $codes);
            break;
        case '3d':
            $result = preg_match('/^[\d]{3}$/', $codes);
            break;
        case 'pcdd':
            $result = preg_match('/^[\d]{3}$/', $codes);
            break;
        case 'k3':
            $result = preg_match('/^[1-6]{3}$/', $codes);
            break;
        case '11x5':
            $data_array = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11'];
            $codes_array = explode(' ', $codes);
            $check_code = true;
            foreach ($codes_array as $code) {
                if (!in_array($code, $data_array, true)) {
                    $check_code = false;
                }
            }
            if ($check_code == false
                || count($codes_array) != 5
                || count($codes_array) != count(array_unique($codes_array))
            ) {
                $result = false;
            } else {
                $result = true;
            }
            break;
        case 'pk10':
            $data_array = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10'];
            $codes_array = explode(' ', $codes);
            $check_code = true;
            foreach ($codes_array as $code) {
                if (!in_array($code, $data_array, true)) {
                    $check_code = false;
                }
            }
            if ($check_code == false
                || count($codes_array) != 10
                || count($codes_array) != count(array_unique($codes_array))
            ) {
                $result = false;
            } else {
                $result = true;
            }
            break;
        case 'kl8':
            $data_array = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10',
                '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
                '21', '22', '23', '24', '25', '26', '27', '28', '29', '30',
                '31', '32', '33', '34', '35', '36', '37', '38', '39', '40',
                '41', '42', '43', '44', '45', '46', '47', '48', '49', '50',
                '51', '52', '53', '54', '55', '56', '57', '58', '59', '60',
                '61', '62', '63', '64', '65', '66', '67', '68', '69', '70',
                '71', '72', '73', '74', '75', '76', '77', '78', '79', '80'];
            $codes_array = explode(' ', $codes);
            $check_code = true;
            foreach ($codes_array as $code) {
                if (!in_array($code, $data_array, true)) {
                    $check_code = false;
                }
            }
            if ($check_code == false
                || count($codes_array) != 20
                || count($codes_array) != count(array_unique($codes_array))
            ) {
                $result = false;
            } else {
                $result = true;
            }
            break;
        case 'lhc':
            $data_array = ['01','02','03','04','05','06','07','08','09','10',
                '11','12','13','14','15','16','17','18','19','20',
                '21','22','23','24','25','26','27','28','29','30',
                '31','32','33','34','35','36','37','38','39','40',
                '41','42','43','44','45','46','47','48','49'];
            $codes_array = explode(' ', $codes);
            $check_code = true;
            foreach ($codes_array as $code) {
                if (!in_array($code, $data_array, true)) {
                    $check_code = false;
                }
            }
            if ($check_code == false
                || count($codes_array) != 7
                || count($codes_array) != count(array_unique($codes_array))
            ) {
                $result = false;
            } else {
                $result = true;
            }
            break;
        case 'kls':
            $data_array = ['01','02','03','04','05','06','07','08','09','10',
                '11','12','13','14','15','16','17','18','19','20'];
            $codes_array = explode(' ', $codes);
            $check_code = true;
            foreach ($codes_array as $code) {
                if (!in_array($code, $data_array, true)) {
                    $check_code = false;
                }
            }
            if ($check_code == false
                || count($codes_array) != 8
                || count($codes_array) != count(array_unique($codes_array))
            ) {
                $result = false;
            } else {
                $result = true;
            }
            break;
    }
    return $result;
}

/**
 * 获取用户使用设备
 */
function get_client_type()
{
    if (stripos(request()->header('user-agent', ''), 'Trusteeship') !== false
        || request()->exists('guaji')) {
        return 4;
    }
    $os = new \apanly\BrowserDetector\Os();
    if (!$os->isMobile()) {
        return 1;
    }
    $os_name = $os->getName();
    switch (strtolower($os_name)) {
        case 'ios':
            return 2;
        case 'android':
            return 3;
        default:
            return 5;
    }
}

/**
 * 二维数组根据某个字段排序
 * @param array $array 要排序的数组
 * @param string $keys   要排序的键字段
 * @param string $sort  排序类型  SORT_ASC     SORT_DESC
 * @return array 排序后的数组
 */
function multi_array_sort($array, $keys, $sort = SORT_DESC)
{
    $keysValue = [];
    foreach ($array as $k => $v) {
        $keysValue[$k] = $v[$keys];
    }
    array_multisort($keysValue, $sort, $array);
    return $array;
}

function array_filter_int($numbers)
{
    if(is_array($numbers)){
        return array_unique(array_filter($numbers, function ($number) {
            return  is_numeric($number) && $number > 0;
        }));
    }
}


/**
 * 检查手机号码
 * @param $cellphone
 * @return bool
 */
function check_cellphone_number($cellphone)
{
    if(preg_match('/^1[3456789]\d{9}$/', $cellphone)) {
        return true;
    } else {
        return false;
    }
}