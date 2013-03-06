var saml2 = require('../'),
fs = require('fs');

var token = fs.readFileSync('./token.xml', 'utf8'); //Remeber to create the token.xml file.

saml2.validate(token, { thumbprint: '1aeabdfa4473ecc7efc5947b19436c575574baf8', realm: 'http://testrealm.com' }, function (err, claims) {
	if (err) {
		console.log(err);
		return;
	};

	console.log(claims);
});