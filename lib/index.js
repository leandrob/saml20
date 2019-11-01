'use strict';

var xml2js = require('xml2js');
var getVersion = require('./getVersion.js');
var validateSignature = require('./validateSignature.js');
var tokenHandlers = {
	'1.1': require('./saml11.js'),
	'2.0': require('./saml20.js')
};

var saml = module.exports;

saml.parse = function parse(rawAssertion, cb) {
	if (!rawAssertion) {
		cb(new Error('rawAssertion is required.'));
		return;
	}

	parseXmlAndVersion(rawAssertion, function onParse(err, assertion, version) {
		if (err) {
			cb(err);
			return;
		}

		parseAttributes(assertion, tokenHandlers[version], cb);
	});
};

saml.validate = function validate(rawAssertion, options, cb) {
	if (!rawAssertion) {
		cb(new Error('rawAssertion is required.'));
		return;
	}

	if (!options || (!options.publicKey && !options.thumbprint)) {
		cb(new Error('publicKey is required.'));
		return;
	}

	if (options.thumbprint) {
		cb(new Error('Validating by thumbprint is currently disabled'));
		return;
	}

	var isSignatureValid = false;

	try {
		isSignatureValid = validateSignature(rawAssertion, options.publicKey, options.thumbprint);
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

	parseXmlAndVersion(rawAssertion, function onParse(err, assertion, version) {
		if (err) {
			cb(err);
			return;
		}

		var tokenHandler = tokenHandlers[version];

		if (!options.bypassExpiration && !tokenHandler.validateExpiration(assertion)) {
			cb(new Error('Assertion is expired.'));
			return;
		}

		if (options.audience && !tokenHandler.validateAudience(assertion, options.audience)) {
			cb(new Error('Invalid audience.'));
			return;
		}

		parseAttributes(assertion, tokenHandler, cb);
	});
};

function parseXmlAndVersion (rawAssertion, cb) {
	var parser = new xml2js.Parser({
		attrkey: '@',
		charKey: '#' ,
		tagNameProcessors:[xml2js.processors.stripPrefix]
	});

	parser.parseString(rawAssertion, function onParse(err, xml) {
		if (err) {
			var error = new Error('An error occurred trying to parse XML assertion.');
			error.inner = err;
			cb(error);
			return;
		}

		xml = xmlBeautify(xml);

		var assertion = xml.Assertion || xml.Response && xml.Response.Assertion;
		var version = getVersion(assertion);

		if (!version) {
			cb(new Error('SAML Assertion version not supported.'));
			return;
		}

		cb(null, assertion, version);
	});
}

function xmlBeautify(obj) {
	Object.keys(obj).forEach(function objectForEach(key) {
		if (obj[key] && obj[key][0] && obj[key].length === 1) {
			obj[key] = obj[key][0];
		}

		if (typeof obj[key] === 'object') {
			return xmlBeautify(obj[key]);
		}
	});

	return obj;
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
