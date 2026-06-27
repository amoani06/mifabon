<?php

declare (strict_types=1);
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
namespace RSSProVendor\Cose;

/**
 * @internal
 */
class Hash
{
    /**
     * Hash Parameter.
     *
     * @var string
     */
    private $hash;
    /**
     * DER encoding T.
     *
     * @var string
     */
    private $t;
    /**
     * Hash Length.
     *
     * @var int
     */
    private $length;
    private function __construct(string $hash, int $length, string $t)
    {
        $this->hash = $hash;
        $this->length = $length;
        $this->t = $t;
    }
    /**
     * @return Hash
     */
    public static function sha1(): self
    {
        return new self('sha1', 20, "0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14");
    }
    /**
     * @return Hash
     */
    public static function sha256(): self
    {
        return new self('sha256', 32, "010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ");
    }
    /**
     * @return Hash
     */
    public static function sha384(): self
    {
        return new self('sha384', 48, "0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040");
    }
    /**
     * @return Hash
     */
    public static function sha512(): self
    {
        return new self('sha512', 64, "0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@");
    }
    public function getLength(): int
    {
        return $this->length;
    }
    /**
     * Compute the HMAC.
     */
    public function hash(string $text): string
    {
        return hash($this->hash, $text, \true);
    }
    public function name(): string
    {
        return $this->hash;
    }
    public function t(): string
    {
        return $this->t;
    }
}
