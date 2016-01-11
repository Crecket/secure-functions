<?php
namespace SecureFuncs;

class SecureFuncs
{

    public static $secret;

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
     * @return md5hash
     */
    public static function getFormToken($id, $token)
    {
        if (empty($_SESSION['formtoken'][$id])) {
            return false;
        }
        return md5($_SESSION['formtoken'][$id]) == $token;
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
     * Sets a new random token using the given id
     * @param $id
     * @return md5hash
     */
    public static function setFormToken($id)
    {
        $_SESSION['formtoken'][$id] = self::randomString(100);
        return md5($_SESSION['formtoken'][$id]);
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
     * @param int $length
     * @return string
     * @throws \Exception
     */
    public static function pseudoBytes($length = 1)
    {
        $bytes = openssl_random_pseudo_bytes($length, $strong);
        if ($strong === TRUE) {
            return $bytes;
        } else {
            throw new \Exception ('Insecure server! (OpenSSL Random byte generation insecure.)');
        }
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

}