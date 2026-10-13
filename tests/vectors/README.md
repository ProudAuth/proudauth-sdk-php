# Signature test vectors

`signatures.json` holds independent test vectors for the PHP SDK's JWS
signature verification. **Every key in it is a test-only key: never configure
these keys anywhere a real token could be accepted.** The file contains no
customer data.

They were generated once by a throwaway Go program (not kept in the
repository) with Go's `crypto/ecdsa`, `crypto/rsa` and `crypto/ed25519`, plus
a hand-built EMSA-PSS encoder for deliberately malformed PSS encodings. Every
expected outcome was then cross-checked with the `openssl` command line (the
same OpenSSL engine the Node SDK verifies with, using `rsa_pss_saltlen:digest`
for PS256). `tests/CryptoVectorsTest.php` runs them.

| Member | Meaning |
| --- | --- |
| `keys[]` | `kid`, `kind` (`RSA`, `EC`, `OKP`), `bits` for RSA, the public `jwk`, and `spki_der_b64`: the SubjectPublicKeyInfo Go's `x509.MarshalPKIXPublicKey` produces for the key. The SDK encodes the same DER from the JWK. |
| `signatures[]` | `name`, `alg`, the `kid` to verify with, the signing `input` (ASCII), the base64url `signature`, whether it is `valid`, and `why` |
| `issuer`, `audience`, `now` | The verifier configuration for `tokens[]` (`now` in Unix seconds) |
| `tokens[]` | Compact access tokens with the expected outcome: `accept` or the SDK error category |

What the vectors cover:

- **ES256:** a valid raw `r || s` signature and its high-S twin (both valid:
  JOSE does not require low-S); tampered input; another key; 63, 65 and 0
  bytes; `r` or `s` equal to 0, to the group order `n` or above it; an ASN.1
  DER signature instead of the JOSE form.
- **PS256:** valid signatures with 2048-, 2049- (the encoded message is one
  byte shorter than the modulus) and 3072-bit keys; tampered input; another
  key; a flipped bit; salt lengths 0, 20, 64 and the maximum (the SDK, like the
  Node SDK, requires a salt as long as the hash: 32 bytes); a wrong trailer
  byte, separator byte or non-zero padding; a PKCS#1 v1.5 signature; signature
  representatives equal to `n`, above `n`, 0 and 1; signatures one byte short
  or long.
- **RS256:** valid 2048- and 4096-bit signatures; tampered input; another key;
  a PSS signature; a truncated signature.
- **EdDSA (Ed25519):** valid; tampered input; another key; 63 bytes; a
  non-canonical scalar (`S + L`).
- **Keys:** a 1024-bit RSA key, which the SDK must skip.
- **Tokens:** valid ES256 and PS256 access tokens (one with the 2049-bit key),
  tokens signed by another key under a known key ID, an ES256 header naming an
  RSA key, a PSS token under a key whose JWK declares RS256, a token under the
  1024-bit key, and an expired token.

The shared access-token fixtures in `sdk/fixtures/access-tokens/cases.json`
cover RS256 and EdDSA end to end; these vectors add ES256 and PS256 and test
each algorithm at the signature level.
