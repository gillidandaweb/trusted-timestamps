<?php

namespace TrustedTimestamps\Test\TestCase;

use PHPUnit\Framework\TestCase;
use TrustedTimestamps\TrustedTimestamps;

class TrustedTimestampsTest extends TestCase
{
    const TSA_URL = 'https://freetsa.org/tsr';

    private $tsaCertificate;
    private $toUnlink = array();

    public function setUp(): void
    {
        $this->tsaCertificate = dirname(dirname(__FILE__)) . '/cacert.pem';
    }

    public function testAll()
    {
        $sha1 = sha1('foo');
        /** @var \PHPUnit\Framework\string|string $requestFile (suppress IDE warning) */
        $requestFile = TrustedTimestamps::createRequestfile($sha1);
        $this->assertFileExists($requestFile);
        $this->toUnlink[] = $requestFile;

        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);
        $this->assertTrue(!empty($signature));
        $this->assertTrue(!empty($signature['response_string']));

        $timestamp = TrustedTimestamps::getTimestampFromAnswer($signature['response_string']);
        $this->assertTrue(!empty($timestamp));

        $valid = TrustedTimestamps::validate($sha1, $signature['response_string'], $signature['response_time'], $this->tsaCertificate);
        $this->assertTrue($valid);

        $sha256 = hash('sha256', 'foo');
        /** @var \PHPUnit\Framework\string|string $requestFile (suppress IDE warning) */
        $requestFile = TrustedTimestamps::createRequestfile($sha256, 'sha256');
        $this->assertFileExists($requestFile);
        $this->toUnlink[] = $requestFile;

        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);
        $this->assertTrue(!empty($signature));
        $this->assertTrue(!empty($signature['response_string']));
    }

    public function testValidateWrongHashStringFails()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/message imprint mismatch/');

        $sha1 = sha1('foo');
        $requestFile = TrustedTimestamps::createRequestfile($sha1);
        $this->toUnlink[] = $requestFile;
        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);

        TrustedTimestamps::validate(sha1('foo1'), $signature['response_string'], $signature['response_time'], $this->tsaCertificate);
    }

    public function testValidateWrongResponseTimeFails()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('The responsetime of the request was changed');

        $sha1 = sha1('foo');
        $requestFile = TrustedTimestamps::createRequestfile($sha1);
        $this->toUnlink[] = $requestFile;
        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);

        TrustedTimestamps::validate($sha1, $signature['response_string'], 1, $this->tsaCertificate);
    }

    public function testValidateWrongResponseStringFails()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/Verification: FAILED/');

        $sha1 = sha1('foo');
        $requestFile = TrustedTimestamps::createRequestfile($sha1);
        $this->toUnlink[] = $requestFile;
        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);

        $wrongRequestFile = TrustedTimestamps::createRequestfile(sha1('foo1'));
        $this->toUnlink[] = $wrongRequestFile;
        $wrongSignature = TrustedTimestamps::signRequestfile($wrongRequestFile, self::TSA_URL);

        TrustedTimestamps::validate($sha1, $wrongSignature['response_string'], $signature['response_time'], $this->tsaCertificate);
    }

    public function tearDown(): void
    {
        parent::tearDown();
        foreach ($this->toUnlink as $file) {
            unlink($file);
        }
    }
}
