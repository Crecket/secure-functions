<?php
namespace SecureFuncs;

class SecureFuncs
{

    /**
     * @var int The key length
     */
    private static $_keyLength = 32;

    /**
     * @param $input
     * @param $key
     * @return string
     * @throws \CannotPerformOperationException
     * @throws \InvalidCiphertextException
     */
    public static function decrypt($input, $key)
    {
        try {
            return \Crypto::decrypt($input, $key);
        } catch (\Defuse\Crypto\Exception\InvalidCiphertextException $ex) {
            die('DANGER! DANGER! The ciphertext has been tampered with!');
        } catch (\Defuse\Crypto\Exception\CryptoTestFailedException $ex) {
            die('Cannot safely perform decryption');
        } catch (\Defuse\Crypto\Exception\CannotPerformOperationException $ex) {
            die('Cannot safely perform decryption');
        }
    }

    /**
     * @param $input
     * @param bool $key
     * @return array
     * @throws CannotPerformOperationException
     * @throws \CannotPerformOperationException
     */
    public static function encrypt($input, $key = false)
    {
        if ($key === false || GenericFuncs::strlen($key) !== Crypto::KEY_BYTE_SIZE) {
            $key = self::randomSecureKey();
        }

        try {
            $ciphertext = \Crypto::encrypt($input, $key);
        } catch (\Defuse\Crypto\Exception\CryptoTestFailedException $ex) {
            die('Cannot safely perform encryption');
        } catch (\Defuse\Crypto\Exception\CannotPerformOperationException $ex) {
            die('Cannot safely perform encryption');
        }

        return array('Key' => $key, 'Encrypted' => $ciphertext);
    }

    /**
     * Checks if the given id and token match > If not the form has been sent twice or the ID is incorrect
     * @param $id
     * @param $limit_time
     * @return md5hash
     */
    public static function getFormToken($id, $token, $limit_time = 300)
    {
        $valid = false;
        // Check if isset
        if (!empty($_SESSION['formtoken'][$id]) && !empty($_SESSION['formtoken_time'][$id])) {
            // Check if token is correct
            if (md5($_SESSION['formtoken'][$id]) === $token) {
                $valid = true;
                // If time limit is set, check if isset
                if ($limit_time !== false) {
                    // if time < limit time return true/false
                    if (empty($_SESSION['formtoken_time'][$id]) || $_SESSION['formtoken_time'][$id] < time() - $limit_time) {
                        $valid = false;
                    }
                }
            }
        }
        unset($_SESSION['formtoken'][$id]);
        unset($_SESSION['formtoken_time'][$id]);
        return $valid;
    }

    /**
     * @param $password -> password to hash
     * @return bool|string
     */
    public static function password_hash($password)
    {
        return password_hash(base64_encode(hash('sha256', $password, true)), PASSWORD_DEFAULT);
    }

    /**
     * @param $password -> password to check
     * @param $hash -> hash to check
     * @return bool
     */
    public static function password_verify($password, $hash)
    {
        return password_verify(base64_encode(hash('sha256', $password, true)), $hash);
    }

    /**
     * @param int $length
     * @return string
     * @throws Exception
     */
    public static function randomHex($length)
    {
        $bytes = \ceil($length / 2);
        $hex = \bin2hex(self::pseudoBytes($bytes));
        return $hex;
    }

    /**
     * @param $min
     * @param $max
     * @return mixed
     * @throws \Exception
     */
    public static function randomInt($min, $max)
    {
        if ($max <= $min) {
            throw new \Exception('Minimum equal or greater than maximum!');
        }
        if ($max < 0 || $min < 0) {
            throw new \Exception('Only positive integers supported for now!');
        }
        $difference = $max - $min;
        for ($power = 8; \pow(2, $power) < $difference; $power = $power * 2) ;
        $powerExp = $power / 8;

        do {
            $randDiff = \hexdec(\bin2hex(self::pseudoBytes($powerExp)));
        } while ($randDiff > $difference);
        return $min + $randDiff;
    }

    /**
     * @return string
     */
    public static function randomSecureKey()
    {
        try {
            return \Crypto::createNewRandomKey();
        } catch (\Defuse\Crypto\Exception\CryptoTestFailedException $ex) {
            die('Cannot safely create a key');
        } catch (\Defuse\Crypto\Exception\CannotPerformOperationException $ex) {
            die('Cannot safely create a key');
        }
    }

    /**
     * @param $length
     * @return string
     * @throws Exception
     */
    public static function randomString($length)
    {

        $charactersArr = \array_merge(\range('a', 'z'), \range('A', 'Z'), \range('0', '9'));

        $charactersCount = \count($charactersArr);

        $stringArr = array();

        for ($character = 0; $character !== $length; $character++) {
            $stringArr[$character] = $charactersArr[self::randomInt(0, $charactersCount - 1)];
        }

        return \implode($stringArr);
    }

    /**
     * Sets a new random token using the given id
     * @param $id
     * @return md5hash
     */
    public static function setFormToken($id)
    {
        $_SESSION['formtoken'][$id] = self::randomString(100);
        $_SESSION['formtoken_time'][$id] = time();
        return md5($_SESSION['formtoken'][$id]);
    }

    /**
     * @param $str
     * @return int
     * @throws CannotPerformOperationException
     */
    public static function strlen($str)
    {
        if (function_exists('mb_strlen')) {
            $length = mb_strlen($str, '8bit');
            if ($length === FALSE) {
                throw new CannotPerformOperationException();
            }
            return $length;
        } else {
            return strlen($str);
        }
    }

    /**
     * @param int $length
     * @return string
     * @throws \Exception
     */
    public static function pseudoBytes($length = 1)
    {
        $bytes = \openssl_random_pseudo_bytes($length, $strong);
        if ($strong === TRUE) {
            return $bytes;
        } else {
            throw new \Exception ('Insecure server! (OpenSSL Random byte generation insecure.)');
        }
    }

    /**
     * Scrypt functions
     *
     * Based on php-scrypt - https://github.com/DomBlack/php-scrypt
     */

    /**
     * Generates a random salt
     *
     * @param int $length The length of the salt
     *
     * @return string The salt
     */
    public static function generateSalt($length = 8)
    {
        $buffer = '';
        $buffer_valid = false;
        if (function_exists('mcrypt_create_iv') && !defined('PHALANGER')) {
            $buffer = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($buffer) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid && function_exists('openssl_random_pseudo_bytes')) {
            $cryptoStrong = false;
            $buffer = openssl_random_pseudo_bytes($length, $cryptoStrong);
            if ($buffer && $cryptoStrong) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid && is_readable('/dev/urandom')) {
            $f = fopen('/dev/urandom', 'r');
            $read = static::strlen($buffer);
            while ($read < $length) {
                $buffer .= fread($f, $length - $read);
                $read = static::strlen($buffer);
            }
            fclose($f);
            if ($read >= $length) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid || static::strlen($buffer) < $length) {
            $bl = static::strlen($buffer);
            for ($i = 0; $i < $length; $i++) {
                if ($i < $bl) {
                    $buffer[$i] = $buffer[$i] ^ chr(mt_rand(0, 255));
                } else {
                    $buffer .= chr(mt_rand(0, 255));
                }
            }
        }
        $salt = str_replace(array('+', '$'), array('.', ''), base64_encode($buffer));

        return $salt;
    }

    /**
     * Create a password hash
     *
     * @param string $password The clear text password
     * @param string|bool $salt The salt to use, or null to generate a random one
     * @param int $N The CPU difficultly (must be a power of 2, > 1)
     * @param int $r The memory difficultly
     * @param int $p The parallel difficultly
     *
     * @throws \Exception
     *
     * @return string The hashed password
     */
    public static function scrypthash($password, $salt = false, $N = 16384, $r = 8, $p = 1)
    {
        // Check if scrypt extension is available
        if (!extension_loaded('scrypt')) {
            throw new \Exception('Missing scrypt extension');
        }

        if ($N == 0 || ($N & ($N - 1)) != 0) {
            throw new \InvalidArgumentException("N must be > 0 and a power of 2");
        }

        if ($N > PHP_INT_MAX / 128 / $r) {
            throw new \InvalidArgumentException("Parameter N is too large");
        }

        if ($r > PHP_INT_MAX / 128 / $p) {
            throw new \InvalidArgumentException("Parameter r is too large");
        }

        if ($salt === false) {
            $salt = self::generateSalt();
        } else {
            // Remove dollar signs from the salt, as we use that as a separator.
            $salt = str_replace(array('+', '$'), array('.', ''), base64_encode($salt));
        }

        $hash = scrypt($password, $salt, $N, $r, $p, self::$_keyLength);

        return $N . '$' . $r . '$' . $p . '$' . $salt . '$' . $hash;
    }

    /**
     * Check a clear text password against a hash
     *
     * @param string $password The clear text password
     * @param string $hash The hashed password
     *
     * @throws \Exception
     *
     * @return boolean If the clear text matches
     */
    public static function scryptcheck($password, $hash)
    {
        // Check if scrypt extension is available
        if (!extension_loaded('scrypt')) {
            throw new \Exception('Missing scrypt extension');
        }

        // Is there actually a hash?
        if (!$hash) {
            return false;
        }

        list ($N, $r, $p, $salt, $hash) = explode('$', $hash);

        // No empty fields?
        if (empty($N) or empty($r) or empty($p) or empty($salt) or empty($hash)) {
            return false;
        }

        // Are numeric values numeric?
        if (!is_numeric($N) or !is_numeric($r) or !is_numeric($p)) {
            return false;
        }

        $calculated = scrypt($password, $salt, $N, $r, $p, self::$_keyLength);

        // Use compareStrings to avoid timeing attacks
        return self::compareStrings($hash, $calculated);
    }

    /**
     * Prevent timing attacks
     *
     * @param string $expected
     * @param string $actual
     *
     * @return boolean If the two strings match.
     */
    public static function compareStrings($expected, $actual)
    {
        $expected = (string)$expected;
        $actual = (string)$actual;
        $lenExpected = static::strlen($expected);
        $lenActual = static::strlen($actual);
        $len = min($lenExpected, $lenActual);

        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;

        return ($result === 0);
    }

}