var assert  = require("assert");
var saml    = require("../lib/index.js");
var fs      = require("fs");

// Tests Configuration
var validToken = fs.readFileSync('./test/assets/validToken.xml').toString();
var invalidToken = fs.readFileSync('./test/assets/invalidToken.xml').toString();

var issuerName = 'https://your-issuer.com';
var thumbprint = '1aeabdfa4473ecc7efc5947b19436c575574baf8';
var certificate = 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgU...';
var audience = 'http://your-service.com/';
var bypassExpiration = true;

describe('SAML 2.0', function() {
	it("Should validate saml 2.0 token using thumbprint", function (done) {
		saml.validate(validToken, { thumbprint: thumbprint, bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.equal(audience, profile.audience);
			assert.ok(profile.claims);
			done();
		})
	});

	it("Should validate saml 2.0 token using certificate", function (done) {
		saml.validate(validToken, { publicKey: certificate, bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.equal(audience, profile.audience);
			assert.ok(profile.claims);
			done();
		})
	});	

	it("Should validate saml 2.0 token and check audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: audience, bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.equal(audience, profile.audience);
			assert.ok(profile.claims);
			done();
		})
	});	

	it("Should fail with invalid audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: 'http://any-other-audience.com/', bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid audience.', err.message);
			done();
		})
	});	

	it("Should fail with invalid signature", function (done) {
		saml.validate(invalidToken, { publicKey: certificate, bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid assertion signature.', err.message);
			done();
		})
	});	

	it("Should fail with invalid assertion", function (done) {
		saml.validate('invalid-assertion', { publicKey: certificate, bypassExpiration: bypassExpiration }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid assertion.', err.message);
			done();
		})
	});	

	it("Should parse saml 2.0 without signature validation", function (done) {
		saml.parse(invalidToken, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.equal(audience, profile.audience);
			assert.ok(profile.claims);
			done();
		})
	});	
})
