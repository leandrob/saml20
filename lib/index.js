var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var getVersion = require('./getVersion.js');
var validateSignature = require('./validateSignature.js');

// Token Handlers for versions supported
var tokenHandlers = {
	'1.1': require('./saml11.js'),
	'2.0': require('./saml20.js')
}

var saml = module.exports;

saml.parse = function (rawAssertion, cb) {

	if (!rawAssertion) {
		cb(new Error('rawAssertion is required.'));
		return;
	};

	parseXmlAndVersion(rawAssertion, function(err, assertion, version){
		if (err) {
			cb(err);
			return;
		};

		parseAttributes(assertion, tokenHandlers[version], cb);
	});
}

saml.validate = function (rawAssertion, options, cb) {

	if (!rawAssertion) {
		cb(new Error('rawAssertion is required.'));
		return;
	};

	if (!options || (!options.publicKey && !options.thumbprint)) {
		cb(new Error('publicKey or thumbprint are options required.'));
		return;
	};

	var isSignatureValid = false;

	try {
		isSignatureValid = validateSignature(rawAssertion, options.publicKey, options.thumbprint)
	}
	catch (e) {
		var error = new Error('Invalid assertion.');
		error.inner = e;
		cb(error);
		return;
	}

	if (!isSignatureValid) {
		cb(new Error('Invalid assertion signature.'));
		return;
	}

	parseXmlAndVersion(rawAssertion, function(err, assertion, version) {
		if (err) {
			cb(err);
			return;
		};

		var tokenHandler = tokenHandlers[version];

		if (!options.bypassExpiration && !tokenHandler.validateExpiration(assertion)) {
			cb(new Error('Assertion is expired.'));
			return;	
		};

		if (options.audience && !tokenHandler.validateAudience(assertion, options.audience)) {
			cb(new Error('Invalid audience.'))
			return;
		};	
		
		parseAttributes(assertion, tokenHandler, cb);
	});
}

function parseXmlAndVersion (rawAssertion, cb) {
	var parser = new xml2js.Parser({ tagNameProcessors:[xml2js.processors.stripPrefix], attrkey:"@", charKey:"#"});

	parser.parseString(rawAssertion, function (err, assertion) {
		if (err) {
			var error = new Error('An error occurred trying to parse XML assertion.');
			error.inner = err;
			cb(error);
			return;
		};

		assertion = assertion.Assertion;

		var version = getVersion(assertion);

		if (!version) {
			cb(new Error('SAML Assertion version not supported.'));
			return;
		};

		cb(null, assertion, version);
	});
}

function parseAttributes(assertion, tokenHandler, cb) {
	var profile = null;

	try {
		profile = tokenHandler.parse(assertion);
	} catch (e) {
		var error = new Error('An error occurred trying to parse assertion.');
		error.inner = e;

		cb(error);
		return;
	}

	cb(null, profile);
}