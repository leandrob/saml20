var assert  = require("assert");
var fs      = require("fs");
var saml    = require("../lib/index.js");

// Tests Configuration
var validToken = fs.readFileSync('./test/assets/saml20.validToken.xml').toString();
var invalidToken = fs.readFileSync('./test/assets/saml20.invalidToken.xml').toString();

var issuerName = 'https://identity.kidozen.com/';
var thumbprint = '1aeabdfa4473ecc7efc5947b19436c575574baf8';
var certificate = 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAMB8xHTAbBgNVBAMTFGlkZW50aXR5LmtpZG96ZW4uY29tMB4XDTEyMDcwNTE4NTEzNFoXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUaWRlbnRpdHkua2lkb3plbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1GPvzmIZ5OO5by9Qn2fsSuLIJWHfewRzgxcZ6SykzmjD4H1aGOtjUg5EFgQ/HWxa16oJ+afWa0dyeXAiLl5gas71FzgzeODL1STIuyLXFVLQvIJX/HTQU+qcMBlwsscdvVaJSYQsI3OC8Ny5GZvt1Jj2G9TzMTg2hLk5OfO1zxAgMBAAGjVDBSMFAGA1UdAQRJMEeAEDSvlNc0zNIzPd7NykB3GAWhITAfMR0wGwYDVQQDExRpZGVudGl0eS5raWRvemVuLmNvbYIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAA4GBAIMmDNzL+Kl5omgxKRTgNWMSZAaMLgAo2GVnZyQ26mc3v+sNHRUJYJzdYOpU6l/P2d9YnijDz7VKfOQzsPu5lHK5s0NiKPaSb07wJBWCNe3iwuUNZg2xg/szhiNSWdq93vKJG1mmeiJSuMlMafJVqxC6K5atypwNNBKbpJEj4w5+';
var audience = 'http://demoscope.com';

describe('lib.saml20', function() {

	it("Should validate saml 2.0 token using thumbprint", function (done) {
		saml.validate(validToken, {publicKey: certificate, thumbprint: thumbprint, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.ok(profile.claims);
			
			assert.strictEqual(issuerName, profile.issuer);
			assert.strictEqual('demo@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
			done();
		})
	});

	it("Should validate saml 2.0 token using certificate", function (done) {
		saml.validate(validToken, { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.strictEqual(issuerName, profile.issuer);
			assert.ok(profile.claims);
			assert.strictEqual('demo@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);

			done();
		})
	});	

	it("Should validate saml 2.0 token and check audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: audience, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.strictEqual(issuerName, profile.issuer);
			assert.ok(profile.claims);
			done();
		})
	});	

	it("Should fail with invalid audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: 'http://any-other-audience.com/', bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.strictEqual('Invalid audience.', err.message);
			done();
		})
	});	

	it("Should fail with invalid signature", function (done) {
		saml.validate(invalidToken, { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.strictEqual('Invalid assertion signature.', err.message);
			done();
		})
	});	

	it("Should fail with invalid assertion", function (done) {
		saml.validate('invalid-assertion', { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.strictEqual('Invalid assertion.', err.message);
			done();
		})
	});	

	it("Should fail with expired assertion", function (done) {
		saml.validate(validToken, { publicKey: certificate }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.strictEqual('Assertion is expired.', err.message);
			done();
		})
	});	

	it("Should parse saml 2.0 without signature validation", function (done) {
		saml.parse(invalidToken, function(err, profile) {
			assert.ifError(err);
			assert.strictEqual(issuerName, profile.issuer);
			assert.ok(profile.claims);
			done();
		})
	});	
})
