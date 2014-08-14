var assert  = require("assert");
var saml    = require("../lib/index.js");
var fs      = require("fs");

// Tests Configuration
var validToken = fs.readFileSync('./test/assets/saml11.validToken.xml').toString();
var invalidToken = fs.readFileSync('./test/assets/saml11.invalidToken.xml').toString();

var issuerName = 'http://ad.kidozen.com/adfs/services/trust';
var thumbprint = '27517ba682aae7496026100d65897d9bb4aea940';
var certificate = 'MIIC+DCCAeCgAwIBAgIQGRZGaEuYQbZKXNjh08hA4TANBgkqhkiG9w0BAQsFADA4MTYwNAYDVQQDEy1BREZTIFNpZ25pbmcgLSBXSU4tRzE2MFU2RzVEQTMuYWQua2lkb3plbi5jb20wHhcNMTQwODA3MTk1MjMxWhcNMTUwODA3MTk1MjMxWjA4MTYwNAYDVQQDEy1BREZTIFNpZ25pbmcgLSBXSU4tRzE2MFU2RzVEQTMuYWQua2lkb3plbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeYA1BZ+FPmTsK3ArgEm7LjfvLKPjMZoFqByM/8w8/yWJ6i1nAjYc9jFm9Sc0kqEg0/P4qzEqGanLkEqHD4TXf/EFkJAV+WXrlAKvhQuvru8b2cDkhFAzJIyHZrf4bkhTwBvOJWhiaK2C0wRLGV6u47lNSKCqmkSX251tQH2eog9WjsiSH/QT0q31I4lDB32tKx90cKtlGEy+rIi838avyOmxF3tQ9m1H+DWjwEn16vaPJuJKJn9iqoG7+JD8nu63l7E+RN+tpAt8MdQ+y+1gylj7Z4Grq0NNpPSbZ078BEGMTY1mmohqBlHm7UU6kK7S4YrCjIz0iePoPqB/mu+HDAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAE+qR3ZTO5EtTMdOepAjAiI8rLZwnUHUScTFZtuHHbEDsX4i6hvzT3p/mzUxm/gDKCFHvLDMCMv1UPB0iGMZZunPAryopekuqCDQz9SmQgSTA4IIzCSKiyRwQjVwby/+5WUA6EYhnTh6fM04kySWE3YmnW8jKhdq+KRXJ0xONGLSrpQ8LL3abcmD3jUiLXvl9okb8b0hXabJSIBXagNqWX3PSmiXiuG0k377aspYGAZbP5ZiuuxNw2ycyA/i1pBQp1FclmebL29dsVoQSrNNljDnCnVEce/Qz2i8zfsEgJBuQE3Qy13dTk9hVhnQFYPru6VIzDc/y0N0TVIcefWQ/uQ=';
var audience = 'http://auth.kidozen.com/';

describe('lib.saml11', function() {

	it("Should validate saml 1.1 token using thumbprint", function (done) {
		saml.validate(validToken, { thumbprint: thumbprint, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.ok(profile.claims);
			assert.equal('lean@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
			done();
		})
	});

	it("Should validate saml 1.1 token using certificate", function (done) {
		saml.validate(validToken, { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.ok(profile.claims);
			assert.equal('lean@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);

			done();
		})
	});	

	it("Should validate saml 1.1 token and check audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: audience, bypassExpiration: true }, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.ok(profile.claims);
			assert.equal('lean@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);

			done();
		})
	});	

	it("Should fail with invalid audience", function (done) {
		saml.validate(validToken, { publicKey: certificate, audience: 'http://any-other-audience.com/', bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid audience.', err.message);
			done();
		})
	});	

	it("Should fail with invalid signature", function (done) {
		saml.validate(invalidToken, { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid assertion signature.', err.message);
			done();
		})
	});	

	it("Should fail with invalid assertion", function (done) {
		saml.validate('invalid-assertion', { publicKey: certificate, bypassExpiration: true }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Invalid assertion.', err.message);
			done();
		})
	});	

	it("Should fail with expired assertion", function (done) {
		saml.validate(validToken, { publicKey: certificate }, function(err, profile) {
			assert.ok(!profile);
			assert.ok(err);
			assert.equal('Assertion is expired.', err.message);
			done();
		})
	});	

	it("Should parse saml 1.1 without signature validation", function (done) {
		saml.parse(invalidToken, function(err, profile) {
			assert.ifError(err);
			assert.equal(issuerName, profile.issuer);
			assert.ok(profile.claims);
			assert.equal('lean22@kidozen.com',profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);

			done();
		})
	});	
})
