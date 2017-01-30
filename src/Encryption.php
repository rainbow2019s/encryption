<?php
namespace encryption;

class Encryption
{

    # ---------------------------------------------------------------------
    # 包含超时的加密解密函数
    # $key1=encryptEncode('abc',60)
    # $key2=encryptDecode($key1,60)
    # 如果超时返回false
    # ---------------------------------------------------------------------

    public static function urlsafeB64encode($string)
    {
        $data = base64_encode($string);
        $data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);
        return $data;
    }

    public static function urlsafeB64decode($string)
    {
        $data = str_replace(array('-', '_', ''), array('+', '/', '='), $string);
        $data = base64_decode($data);
        return $data;
    }

    /**
     * 加密
     * @param string $string        要加密或解密的字符串
     * @param string $operation     加密 ''  解密 DECODE
     * @param string $key           密钥，加密解密时保持一致
     * @param int    $expiry        有效时长，单位：秒
     * @return string
     */
    public static function encryptEncode($string, $expiry = 0, $key = 'q97fqIQNmJWhxmrHkpTs')
    {
        $ckey_length = 7;
        $key         = md5($key ? $key : UC_KEY); //加密解密时这个是不变的
        $keya        = md5(substr($key, 0, 16)); //加密解密时这个是不变的
        $keyb        = md5(substr($key, 16, 16)); //加密解密时这个是不变的
        $keyc        = $ckey_length ? substr(md5(microtime()), -$ckey_length) : '';
        $cryptkey    = $keya . md5($keya . $keyc); //64
        $key_length  = strlen($cryptkey); //64

        $string        = sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);

        $result = '';
        $box    = range(0, 255);

        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            //字母表 64位后重复 数列 范围为48~122
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }

        for ($j = $i = 0; $i < 256; $i++) {
            //这里是一个打乱算法
            $j       = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp     = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $result .= chr(ord($string[$i]) ^ ($box[$i]));

        }
        $str = $keyc . str_replace('=', '', self::urlsafeB64encode($result));
        //  $str =htmlentities($str, ENT_QUOTES, "UTF-8"); // curl 访问出错
        return $str;
    }

    /**
     * 解密
     * @param string $string     要加密或解密的字符串
     * @param string $operation  加密 ''  解密 DECODE
     * @param string $key        密钥，加密解密时保持一致
     * @param int    $expiry     有效时长，单位：秒
     * @return string
     */
    public static function encryptDecode($string, $expiry = 0, $key = 'q97fqIQNmJWhxmrHkpTs')
    {
        //  $string = html_entity_decode($string, ENT_QUOTES, "UTF-8") ; //curl 访问出错
        $ckey_length = 7;
        $key         = md5($key ? $key : UC_KEY); //加密解密时这个是不变的
        $keya        = md5(substr($key, 0, 16)); //加密解密时这个是不变的
        $keyb        = md5(substr($key, 16, 16)); //加密解密时这个是不变的

        $keyc = $ckey_length ? substr($string, 0, $ckey_length) : '';

        $cryptkey      = $keya . md5($keya . $keyc); //64
        $key_length    = strlen($cryptkey); //64
        $string        = self::urlsafeB64decode(substr($string, $ckey_length));
        $string_length = strlen($string);
        $result        = '';
        $box           = range(0, 255);

        $rndkey = array();
        for ($i = 0; $i <= 255; $i++) {
            //字母表 64位后重复 数列 范围为48~122
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            //这里是一个打乱算法
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;

            $tmp     = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $result .= chr(ord($string[$i]) ^ ($box[$i]));
        }

        if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return false;
        }

    }

    # ---------------------------------------------------------------------
    # URL加密解密函数
    # $key1=encodeUrl('http://www.baidu.com')
    # decodeUrl($key1)
    # ---------------------------------------------------------------------

    //加密函数
    public static function encodeUrl($txt, $key = 'Uso9JK1zZy68n5JTbeFl')
    {
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
        $nh    = rand(0, 64);
        $ch    = $chars[$nh];
        $mdKey = md5($key . $ch);
        $mdKey = substr($mdKey, $nh % 8, $nh % 8 + 7);
        $txt   = base64_encode($txt);
        $tmp   = '';
        $i     = 0;
        $j     = 0;
        $k     = 0;
        for ($i = 0; $i < strlen($txt); $i++) {
            $k = $k == strlen($mdKey) ? 0 : $k;
            $j = ($nh + strpos($chars, $txt[$i]) + ord($mdKey[$k++])) % 64;
            $tmp .= $chars[$j];
        }
        return urlencode($ch . $tmp);
    }

    //解密函数
    public static function decodeUrl($txt, $key = 'Uso9JK1zZy68n5JTbeFl')
    {
        $txt   = urldecode($txt);
        $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+";
        $ch    = $txt[0];
        $nh    = strpos($chars, $ch);
        $mdKey = md5($key . $ch);
        $mdKey = substr($mdKey, $nh % 8, $nh % 8 + 7);
        $txt   = substr($txt, 1);
        $tmp   = '';
        $i     = 0;
        $j     = 0;
        $k     = 0;
        for ($i = 0; $i < strlen($txt); $i++) {
            $k = $k == strlen($mdKey) ? 0 : $k;
            $j = strpos($chars, $txt[$i]) - $nh - ord($mdKey[$k++]);
            while ($j < 0) {
                $j += 64;
            }

            $tmp .= $chars[$j];
        }
        return base64_decode($tmp);
    }

    # ---------------------------------------------------------------------
    # 用户密码可逆加密解密函数
    # 用户密码 123456 加密key 无
    # $key1=encodePassport('123456')
    # $key2=decodePassport($key1)
    # ---------------------------------------------------------------------

    public static function encryptPassport($txt, $key = '04lAsrkwJ7ruzub2nHmd')
    {
        srand((double) microtime() * 1000000);
        $encrypt_key = md5(rand(0, 32000));
        $ctr         = 0;
        $tmp         = '';
        for ($i = 0; $i < strlen($txt); $i++) {
            $ctr = $ctr == strlen($encrypt_key) ? 0 : $ctr;
            $tmp .= $encrypt_key[$ctr] . ($txt[$i] ^ $encrypt_key[$ctr++]);
        }
        return urlencode(base64_encode(self::keyPassport($tmp, $key)));
    }

    public static function decryptPassport($txt, $key = '04lAsrkwJ7ruzub2nHmd')
    {
        $txt = self::keyPassport(base64_decode(urldecode($txt)), $key);
        $tmp = '';
        for ($i = 0; $i < strlen($txt); $i++) {
            $md5 = $txt[$i];
            $tmp .= $txt[++$i] ^ $md5;
        }
        return $tmp;
    }

    public static function keyPassport($txt, $encrypt_key)
    {
        $encrypt_key = md5($encrypt_key);
        $ctr         = 0;
        $tmp         = '';
        for ($i = 0; $i < strlen($txt); $i++) {
            $ctr = $ctr == strlen($encrypt_key) ? 0 : $ctr;
            $tmp .= $txt[$i] ^ $encrypt_key[$ctr++];
        }
        return $tmp;
    }

    # ---------------------------------------------------------------------
    # SHA1的可逆加密解密函数
    # $key1=SHA1('1234',true) 加密
    # $key2=SHA1($key1,false) 解密
    # ---------------------------------------------------------------------

    public static function sha1($string, $isEncrypt = true, $key = '68rIAiCUve9mtv7Pf5gy')
    {
        if (!isset($string{0}) || !isset($key{0})) {
            return false;
        }

        $dynKey   = $isEncrypt ? hash('sha1', microtime(true)) : substr($string, 0, 40);
        $fixedKey = hash('sha1', $key);

        $dynKeyPart1   = substr($dynKey, 0, 20);
        $dynKeyPart2   = substr($dynKey, 20);
        $fixedKeyPart1 = substr($fixedKey, 0, 20);
        $fixedKeyPart2 = substr($fixedKey, 20);
        $key           = hash('sha1', $dynKeyPart1 . $fixedKeyPart1 . $dynKeyPart2 . $fixedKeyPart2);

        $string = $isEncrypt ? $fixedKeyPart1 . $string . $dynKeyPart2 : (isset($string{339}) ? gzuncompress(base64_decode(substr($string, 40))) : base64_decode(substr($string, 40)));

        $n      = 0;
        $result = '';
        $len    = strlen($string);

        for ($n = 0; $n < $len; $n++) {
            $result .= chr(ord($string{$n}) ^ ord($key{$n % 40}));
        }
        return $isEncrypt ? $dynKey . str_replace('=', '', base64_encode($n > 299 ? gzcompress($result) : $result)) : substr($result, 20, -20);
    }

    # ---------------------------------------------------------------------
    # DES的加密解密函数
    # $key1=SHA1('1234',true) 加密
    # $key2=SHA1($key1,false) 解密
    # ---------------------------------------------------------------------

    public static function random($length = 4)
    {
        $pattern = '1234567890';
        for ($i = 0; $i < $length; $i++) {
            @$key .= $pattern{rand(0, 9)}; //生成php随机数
        }
        return $key;
    }

    public static function desEncrypt($input, $key)
    {
        $input = base64_encode(trim($input));
        //$key = substr(md5($key), 0, 4);
        $td = mcrypt_module_open('des', '', 'ecb', '');
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $key, $iv);
        $encrypted_data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return trim(base64_encode($encrypted_data));
    }

    public static function desDecrypt($input, $key)
    {
        $input = base64_decode(trim($input));
        $td    = mcrypt_module_open('des', '', 'ecb', '');
        //$key = substr(md5($key), 0, 4);
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $key, $iv);
        $decrypted_data = mdecrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return trim(base64_decode($decrypted_data));
    }

}
