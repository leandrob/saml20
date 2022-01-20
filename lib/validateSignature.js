'use strict';

var select = require('xml-crypto').xpath;
var SignedXml = require('xml-crypto').SignedXml;
var Dom = require('@xmldom/xmldom').DOMParser;
var thumbprint = require('thumbprint');

module.exports = function validateSignature(xml, cert, certThumbprint) {
  var doc = new Dom().parseFromString(xml);
  var signature = select(doc, '/*/*/*[local-name(.)=\'Signature\' and namespace-uri(.)=\'http://www.w3.org/2000/09/xmldsig#\']')[0]
    || select(doc, '/*/*[local-name(.)=\'Signature\' and namespace-uri(.)=\'http://www.w3.org/2000/09/xmldsig#\']')[0];
  var signed = new SignedXml(null, {
    idAttribute: 'AssertionID'
  });

  var calculatedThumbprint;

  signed.keyInfoProvider = {
    getKey: function getKey(keyInfo) {
      if (certThumbprint) {
        var embeddedSignature = keyInfo[0].getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');

        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();

          calculatedThumbprint = thumbprint.calculate(base64cer);

          return certToPEM(base64cer);
        }
      }

      return certToPEM(cert);
    },
    getKeyInfo: function getKeyInfo(key) {
      return '<X509Data></X509Data>';
    }
  };

  signed.loadSignature(signature.toString());

  var valid = signed.checkSignature(xml);

  if (cert) {
    return valid;
  }

  if (certThumbprint) {
    return valid && calculatedThumbprint.toUpperCase() === certThumbprint.toUpperCase();
  }
};

function certToPEM(cert) {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
}
