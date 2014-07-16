var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');

module.exports = function (xml, cert, thumbprint) {

	var doc = new xmldom.DOMParser().parseFromString(xml);
	var signature = xmlCrypto.xpath.SelectNodes(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];

	var signed = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });

	var calculatedThumbprint;

	signed.keyInfoProvider = {
		getKeyInfo: function (key) {
			return "<X509Data></X509Data>"
		},
		getKey: function (keyInfo) {
			if (thumbprint)  {
				var embeddedSignature = keyInfo[0].getElementsByTagName("X509Certificate");

				if (embeddedSignature.length > 0) {
					var base64cer = embeddedSignature[0].firstChild.toString();
					
					calculatedThumbprint = calculateThumbprint(base64cer);

					return certToPEM(base64cer);
				}
			}

			return certToPEM(cert);
		}
	};

	signed.loadSignature(signature.toString());
	
	var valid = signed.checkSignature(xml);

	if (cert) {
		return valid;
	}

	if (thumbprint) {
		return valid && calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
	}
}

function calculateThumbprint(cert) {
	var shasum = crypto.createHash('sha1');
	var der = new Buffer(cert, 'base64').toString('binary')
	shasum.update(der);
	
	return shasum.digest('hex');
}

function certToPEM(cert) {
	if (cert.indexOf("BEGIN CERTIFICATE")===-1 & cert.indexOf("END CERTIFICATE")===-1){
		cert = cert.match(/.{1,64}/g).join('\n');
		cert = "-----BEGIN CERTIFICATE-----\n" + cert;
		cert = cert + "\n-----END CERTIFICATE-----\n";
		return cert;
 	} else {
 		return cert;
 	}
};