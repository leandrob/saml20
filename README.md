SAML 2.0 & 1.1 Assertion Parser & Validator
=============
saml20 is a simple module that allows you to parse and validate SAML 2.0 and 1.1 tokens. It has been tested with [Microsoft ADFS](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services), OKTA, and PingOne tokens.

## Installation

```bash
$ npm install saml20
```

## Usage

### saml.parse(rawAssertion, cb)

`rawAssertion` is the SAML Assertion in string format.

Parses the `rawAssertion` without validating signature, expiration and audience. It allows you to get information from the token like the Issuer name in order to obtain the right public key to validate the token in a multi-providers scenario.

```javascript

var saml = require('saml20');

saml.parse(rawAssertion, function(err, profile) {
	// err

	var claims = profile.claims; // Array of user attributes;
	var issuer = profile.issuer; // String Issuer name.
});

```

### saml.validate(rawAssertion, options, cb)

`rawAssertion` is the SAML Assertion in string format.

`options`:

* `thumbprint` is the thumbprint of the trusted public key (uses the public key that comes in the assertion).
* `publicKey` is the trusted public key.
* `audience` (optional). If it is included audience validation will take place.
* `bypassExpiration` (optional). This flag indicates expiration validation bypass (useful for testing, not recommended in production environments);

You can use either `thumbprint` or `publicKey` but you should use at least one.

```javascript

var saml = require('saml20');

var options = {
	thumbprint: '1aeabdfa4473ecc7efc5947b18436c575574baf8',
	audience: 'http://myservice.com/'
}

saml.validate(rawAssertion, options, function(err, profile) {
	// err

	var claims = profile.claims; // Array of user attributes;
	var issuer = profile.issuer; // String Issuer name.
});

```

or using publicKey:

```javascript

var saml = require('saml20');

var options = {
	publicKey: 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5Bc...',
	audience: 'http://myservice.com/'
}

saml.validate(rawAssertion, options, function(err, profile) {
	// err

	var claims = profile.claims; // Array of user attributes;
	var issuer = profile.issuer; // String Issuer name.
});

```

## Tests

### Configure test/lib.index.js

In order to run the tests you must configure `lib.index.js` with these variables:

```javascript

var issuerName = 'https://your-issuer.com';
var thumbprint = '1aeabdfa4473ecc7efc5947b19436c575574baf8';
var certificate = 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgU...';
var audience = 'http://your-service.com/';

```

You also need to include a valid and an invalid SAML 2.0 token on `test/assets/invalidToken.xml` and test/assets/validToken.xml`

```xml

<Assertion ID="_1308c268-38e2-4849-9957-b7babd4a0659" IssueInstant="2014-03-01T04:04:52.919Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://your-issuer.com/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_1308c268-38e2-4849-9957-b7babd4a0659"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>qJQjAuaj7adyLkl6m3T1oRhtYytu4bebq9JcQObZIu8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>amPTOSqkEq5ppbCyUgGgm....</Assertion>

```

To run the tests use:

```bash
$ npm test
```

## License

MIT
