<?php
require __DIR__ . '/../vendor/autoload.php';

class test extends PHPUnit_Framework_TestCase
{

    public function testEncryptDecrypt()
    {

        $message = "1234567890abcdefghijklmnopqrstuvwxyz";
        $encryptedData = SecureFuncs\SecureFuncs::encrypt($message);

        $this->assertArrayHasKey('Key', $encryptedData);

        $this->assertNotEmpty($encryptedData['Key']);

        $this->assertArrayHasKey('Encrypted', $encryptedData);

        $this->assertNotEmpty($encryptedData['Encrypted']);

        $decryptedText = SecureFuncs\SecureFuncs::decrypt($encryptedData['Encrypted'], $encryptedData['Key']);

        $this->assertEquals($message, $decryptedText);

    }

    public function testRandom()
    {

        $this->assertNotEmpty(\SecureFuncs\SecureFuncs::pseudoBytes(32));

        $this->assertStringMatchesFormat('%s', \SecureFuncs\SecureFuncs::randomHex(32));

        $this->assertStringMatchesFormat('%s', \SecureFuncs\SecureFuncs::randomString(32));

        $this->assertInternalType('int', \SecureFuncs\SecureFuncs::randomInt(32, 64));

    }

    public function testPassword()
    {

        $password = "qwerty1234567";

        $hash = \SecureFuncs\SecureFuncs::password_hash($password);

        $this->assertInternalType('string', $hash);

        $this->assertTrue(\SecureFuncs\SecureFuncs::password_verify($password, $hash));

    }

    public function testOther()
    {
        $this->assertEquals(9, \SecureFuncs\SecureFuncs::strlen('123456789'));
    }

}