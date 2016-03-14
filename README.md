# secure-functions
[![Latest Stable Version](https://img.shields.io/packagist/v/crecket/secure-functions.svg)](https://packagist.org/packages/crecket/secure-functions)
[![Build Status](https://travis-ci.org/Crecket/secure-functions.svg?branch=master)](https://travis-ci.org/Crecket/secure-functions)

A collection of functions which can be used for security purposes.

## Instalation

#### Composer
Install through composer and require the autoloader.

`composer require crecket/secure-functions`

#### Manual
Download the files and require them in your project.

`require '/secure-functions/src/SecureFuncs.php';`

## Usage
All functions are static public functions right now so you can simply call the functions like this:

`SecureFuncs\SecureFuncs::password_hash('input');`

## Functions

### decrypt($input, $key)
Returns the decryped output as a string using [defuse/php-encryption](https://github.com/defuse/php-encryption)'s library.

### encrypt($input, $key = false)
Encrypt a string, if no key is given one will be generated for you (Recommended) using [defuse/php-encryption](https://github.com/defuse/php-encryption)'s library.

### getFormToken('form_token_id', $_POST['form_token'], $limit = false)
Verify a form token for the given id. The $limit is optional andm ust be given in seconds, if the limit is 300 and the token is used after 300 seconds it will be considered invalid.

### password_hash($password)
Hash the given password. This function allows for longer passwords and isn't affected by the null-byte issue.

### password_verify($password, $hash)
Verify the given password hash

### randomHex($length)
Returns a random hexadecimal number for the given length

### randomInt($min, $max)
Returns the a secure random integer within the given range.

### randomSecureKey()
Return a random key using [defuse/php-encryption](https://github.com/defuse/php-encryption)'s library.

### randomString($length)
Returns a random string for the given length

### setFormToken($id)
Set a unique token in the session and returns it, can be used to verify post/get requests

### strlen($str)
Returns the length of the given string using mb_strlen when available

### pseudoBytes($length)
Returns random bytes for the given length


