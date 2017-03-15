'use strict';
/**
 * EC key
 */

const _ = require('lodash');
const base64url = require('base64url');

const SUPPORTED_CURVES = [
	'P-256',
	'P-384',
	'P-521'
];

class ECKey {

	constructor(crv, x, y, d) {
		this._crv = crv;
		this._x = x;
		this._y = y;
		this._d = d;
	}

	get hasPrivateKey() {
		return !_.isNil(this._d);
	}

	static validate(key) {
		// y must only be defined for the three curves defined in RFC-7517 par. 6.2.1
		// FIXME: Currently y is treated as mandatory here.
		return _.has(key, 'crv') && _.has(key, 'x')  && _.has(key, 'y') && _.includes(SUPPORTED_CURVES, key.crv);
	}

	static fromKey(key) {
		const x = base64url.toBuffer(key.x);
		const y = base64url.toBuffer(key.y);
		const d = key.d ? base64url.toBuffer(key.d) : undefined;

		return new ECKey(key.crv, x, y, d);
	}

}

module.exports = ECKey;
