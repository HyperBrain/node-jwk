# node-jwk

Implementation of RFC-7517 (JSON Web Key) compliant key handling.

The module can be used to convert keys into buffers or other formats to
enable the direct use of JWK formatted keys with other node modules like
[njwt](https://www.npmjs.com/package/njwt) and others.

## Usage

_will come_

## Documentation

_will come_

## Examples

### Creating a signed token with node-jwk and njwt

The example uses bluebird promises to be able to catch exceptions thrown in the
key retrieval and lodash for convenience.

```
const time = Math.floor(_.now() / 1000);

const claims = {
	iss: 'itsME',
	aud: 'myAudience',
	iat: time,
	exp: time + 3600
};

return BbPromise.try(() => {
	const keySet = nodeJWK.JWKSet.fromObject(myPrivateKeySet);
	const jwk = keySet.findKeyById(myKeyId);

	if (!jwk) {
		return BbPromise.reject(new Error('Huh, my key is not there...'));
	}

	const keyPEM = jwk.key.toPrivateKeyPEM();
	const jwt = njwt.create(claims, keyPEM, jwk.alg);

	return BbPromise.resolve(jwt.compact());
})
.catch(err => {
	return BbPromise.reject(err);
});
```

## Supported key types

RSA, EC, oct

All keys but binary (oct) keys can be converted into PEM format for their
public and private keys.

## References

[RFC-7517 JSON Web Key](https://tools.ietf.org/html/rfc7517)

[RFC-7518 JSON Web Algorithms](https://tools.ietf.org/html/rfc7518)
