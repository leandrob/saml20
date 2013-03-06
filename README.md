saml20
=============
saml20 is a simple module that allows you to parse and validate SAML 2.0 and 1.1 tokens. The code is based on Matias Woloski's [passport-wsfed-saml2](https://github.com/auth10/passport-wsfed-saml2) library, I've just extracted the SAML validation functionality in an independent module.

It can be used with [Microsoft ADFS](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services) tokens.

## Installation

    $ npm install saml20

## Usage

```javascript

var saml20 = require('saml20');

var options = {
	cert: 'MIICDzCCAXygAwIB...pJEj4w5==', // Public key in base64
	realm: 'http://yourrealm.com'	
};

saml20.validate(samlAssertion, options, function(err, user) {
	// if validation is successful user will contain user claims.
});

```
If you want to use the certificate information that comes in the SAML assertion you can use certificate thumbprint instead of specifying the certificate.

```javascript

var saml20 = require('saml20');

var options = {
	thumbprint: '1aeabdfa4473ecc7efc5947b19436c575574baf8',
	realm: 'http://yourrealm.com'	
};

saml20.validate(samlAssertion, options, function(err, claims) {
	// if validation is successful claims will be an array that contains.
});
