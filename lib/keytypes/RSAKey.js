'use strict';
/**
 * RSA key
 */

const _ = require('lodash');
const base64url = require('base64url');

const OPTIONAL_PRIVATE_PROPS = [
	'p', 'q', 'dp', 'dq', 'qi'
];

class RSAKey {

	constructor(n, e, d, p, q, dp, dq, qi, oth) {
		this._n = n;
		this._e = e;
		this._d = d;
		this._p = p;
		this._q = q;
		this._dp = dp;
		this._dq = dq;
		this._qi = qi;
		this._oth = oth;
	}

	get hasPrivateKey() {
		return !_.isNil(this._d);
	}

	static validate(key) {
		// @see RFC-7517 par. 6.3
		let result = _.has(key, 'n') && _.has(key, 'e');

		// RFC-7517 6.3.2:
		// If the producer includes any of the other private key parameters, then
		// all of the others MUST be present, with the exception of "oth"
		result = result &&
			(!_.has(key, 'd') ||
				_.some(OPTIONAL_PRIVATE_PROPS, prop => _.has(key, prop)) && _.every(OPTIONAL_PRIVATE_PROPS, prop => _.has(key, prop)));

		return result;
	}

	static fromKey(key) {
		const x = base64url.toBuffer(key.x);
		const y = base64url.toBuffer(key.y);
		const d = key.d ? base64url.toBuffer(key.d) : undefined;

		return new RSAKey(key.crv, x, y, d);
	}

}

module.exports = RSAKey;
