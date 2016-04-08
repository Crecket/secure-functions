<?php
require __DIR__ . '/../vendor/autoload.php';

class test extends PHPUnit_Framework_TestCase
{

    public function testRandom()
    {

        $this->assertNotEmpty(\SecureFuncs\SecureFuncs::pseudoBytes(32));

        $this->assertStringMatchesFormat('%s', \SecureFuncs\SecureFuncs::randomHex(32));

        $this->assertStringMatchesFormat('%s', \SecureFuncs\SecureFuncs::randomString(32));

        $this->assertInternalType('int', \SecureFuncs\SecureFuncs::randomInt(32, 64));

    }

    public function testPassword()
    {

        $password = \SecureFuncs\SecureFuncs::randomString(32);

        $hash = \SecureFuncs\SecureFuncs::password_hash($password);

        $this->assertInternalType('string', $hash);

        $this->assertTrue(\SecureFuncs\SecureFuncs::password_verify($password, $hash));

    }

    public function testOther()
    {
        $this->assertEquals(9, \SecureFuncs\SecureFuncs::strlen('123456789'));
    }

    public function testCompareStrings()
    {
        $random_string = \SecureFuncs\SecureFuncs::randomString(12);
        $this->assertTrue(\SecureFuncs\SecureFuncs::compareStrings($random_string, $random_string));
    }
}