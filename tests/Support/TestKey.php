<?php

declare(strict_types=1);

namespace ProudAuth\Sdk\Tests\Support;

/**
 * A test-only key pair with its public JWK, and test-only signing. Signing
 * exists only here, in the tests: the SDK itself never signs.
 */
final class TestKey
{
    /**
     * @param \OpenSSLAsymmetricKey|string $private an OpenSSL private key, or a 64-byte libsodium Ed25519 secret key
     * @param array<string, mixed>         $jwk
     */
    private function __construct(
        public readonly string $kid,
        public readonly string $alg,
        private readonly \OpenSSLAsymmetricKey|string $private,
        public readonly array $jwk,
    ) {
    }

    public static function make(string $alg, ?string $kid = null, bool $jwkAlg = true, int $rsaBits = 2048): self
    {
        $kid ??= strtolower($alg) . '-' . bin2hex(random_bytes(4));
        switch ($alg) {
            case 'ES256':
                $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
                if ($key === false) {
                    throw new \RuntimeException('EC key generation failed');
                }
                $d = openssl_pkey_get_details($key);
                $jwk = [
                    'kty' => 'EC', 'crv' => 'P-256',
                    'x' => Jwt::b64(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
                    'y' => Jwt::b64(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT)),
                ];
                break;
            case 'RS256':
            case 'PS256':
                $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $rsaBits]);
                if ($key === false) {
                    throw new \RuntimeException('RSA key generation failed');
                }
                $d = openssl_pkey_get_details($key);
                $jwk = ['kty' => 'RSA', 'n' => Jwt::b64($d['rsa']['n']), 'e' => Jwt::b64($d['rsa']['e'])];
                break;
            case 'EdDSA':
                $pair = sodium_crypto_sign_keypair();
                $key = sodium_crypto_sign_secretkey($pair);
                $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jwt::b64(sodium_crypto_sign_publickey($pair))];
                break;
            default:
                throw new \InvalidArgumentException('unsupported test alg ' . $alg);
        }
        $jwk['kid'] = $kid;
        $jwk['use'] = 'sig';
        if ($jwkAlg) {
            $jwk['alg'] = $alg;
        }
        return new self($kid, $alg, $key, $jwk);
    }

    /** The private key as a JWK (for "private key in the key set" tests). */
    public function privateJwk(): array
    {
        if (!$this->private instanceof \OpenSSLAsymmetricKey) {
            return $this->jwk + ['d' => Jwt::b64(substr($this->private, 0, 32))];
        }
        $d = openssl_pkey_get_details($this->private);
        if (isset($d['ec'])) {
            return $this->jwk + ['d' => Jwt::b64(str_pad($d['ec']['d'], 32, "\0", STR_PAD_LEFT))];
        }
        return $this->jwk + ['d' => Jwt::b64($d['rsa']['d']), 'p' => Jwt::b64($d['rsa']['p']), 'q' => Jwt::b64($d['rsa']['q'])];
    }

    /** A copy of this key presented under another algorithm (same key material). */
    public function asAlg(string $alg): self
    {
        return new self($this->kid, $alg, $this->private, $this->jwk);
    }

    public function sign(string $data, ?string $alg = null): string
    {
        $alg ??= $this->alg;
        if ($alg === 'EdDSA') {
            if (!is_string($this->private)) {
                throw new \LogicException('not an Ed25519 key');
            }
            return sodium_crypto_sign_detached($data, $this->private);
        }
        if (!$this->private instanceof \OpenSSLAsymmetricKey) {
            throw new \LogicException('not an OpenSSL key');
        }
        switch ($alg) {
            case 'RS256':
                openssl_sign($data, $sig, $this->private, OPENSSL_ALGO_SHA256);
                return $sig;
            case 'ES256':
                openssl_sign($data, $der, $this->private, OPENSSL_ALGO_SHA256);
                return self::derToRaw($der);
            case 'PS256':
                return $this->signPss($data);
            default:
                throw new \InvalidArgumentException('unsupported test alg ' . $alg);
        }
    }

    /** ECDSA-Sig-Value (DER) to the JWS r || s form. */
    private static function derToRaw(string $der): string
    {
        $pos = 2; // SEQUENCE tag and (short) length
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            $len = ord($der[$pos + 1]);
            $int = ltrim(substr($der, $pos + 2, $len), "\0");
            $out .= str_pad($int, 32, "\0", STR_PAD_LEFT);
            $pos += 2 + $len;
        }
        return $out;
    }

    /** EMSA-PSS-ENCODE (SHA-256, MGF1-SHA-256, 32-byte salt) and the raw RSA private operation. */
    private function signPss(string $data): string
    {
        $d = openssl_pkey_get_details($this->private);
        $n = ltrim($d['rsa']['n'], "\0");
        $modBits = (strlen($n) - 1) * 8 + strlen(decbin(ord($n[0])));
        $k = intdiv($modBits + 7, 8);
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        $salt = random_bytes(32);
        $h = hash('sha256', str_repeat("\0", 8) . hash('sha256', $data, true) . $salt, true);
        $db = str_repeat("\0", $emLen - 32 - 32 - 2) . "\x01" . $salt;
        $mask = '';
        for ($c = 0; strlen($mask) < strlen($db); $c++) {
            $mask .= hash('sha256', $h . pack('N', $c), true);
        }
        $db ^= substr($mask, 0, strlen($db));
        $db[0] = chr(ord($db[0]) & (0xff >> (8 * $emLen - $emBits)));
        $em = str_repeat("\0", $k - $emLen) . $db . $h . "\xbc";
        if (!openssl_private_encrypt($em, $sig, $this->private, OPENSSL_NO_PADDING)) {
            throw new \RuntimeException('raw RSA failed');
        }
        return $sig;
    }
}
