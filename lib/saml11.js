'use strict';

var _ = require('lodash');
var saml11 = module.exports;

saml11.parse = function parse(assertion) {
	var claims = {};
	var attributes = _.get(assertion, 'AttributeStatement.Attribute');

	if (attributes) {
		attributes = (attributes instanceof Array) ? attributes : [attributes];

		attributes.forEach(function attributesForEach(attribute) {
			var attributeName = attribute['@'].AttributeNamespace + '/' + attribute['@'].AttributeName;

			if (attribute.AttributeValue) {
				claims[attributeName] = attribute.AttributeValue._ || attribute.AttributeValue;
			}
		});
	}

	var nameIdentifier = _.get(assertion, 'AttributeStament.Subject.NameIdentifier');

	if (nameIdentifier) {
		claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = nameIdentifier._ || nameIdentifier;
	}

	return {
		audience: getAudience(assertion),
		claims: claims,
		issuer: assertion['@'].Issuer
	};
};

function getAudience(assertion) {
	if (assertion.Conditions.AudienceRestrictionCondition) {
		return assertion.Conditions.AudienceRestrictionCondition.Audience;
	} else {
		return undefined;
	}
}

saml11.validateAudience = function validateAudience(assertion, realm) {
	var audience = getAudience(assertion);
	if (Array.isArray(realm)) {
		return realm.indexOf(audience) !== -1;
	}

  return audience === realm;
};

saml11.validateExpiration = function validateExpiration(assertion) {
	var notBefore = new Date(assertion.Conditions['@'].NotBefore);
	notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew

	var notOnOrAfter = new Date(assertion.Conditions['@'].NotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

  var now = new Date();

  return !(now < notBefore || now > notOnOrAfter);
 };
