# node-jwk

Implementation of RFC-7517 (JSON Web Key) compliant key handling.

The module can be used to convert keys into buffers or other formats to
enable the direct use of JWK formatted keys with other node modules like
[njwt](https://www.npmjs.com/package/njwt) and others.

## Usage

_will come_

## Documentation

_will come_

## Supported key types

RSA, EC, oct

All keys but binary (oct) keys can be converted into PEM format for their
public and private keys.

## References

[RFC-7517 JSON Web Key](https://tools.ietf.org/html/rfc7517)

[RFC-7518 JSON Web Algorithms](https://tools.ietf.org/html/rfc7518)
