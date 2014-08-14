var nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

var saml20 = module.exports;

saml20.parse = function (assertion) {
	var claims = {};

	if (assertion.AttributeStatement && assertion.AttributeStatement.length > 0) {
		var attributes = assertion.AttributeStatement[0].Attribute;

		if (attributes) {
			attributes  = (attributes instanceof Array) ? attributes : [attributes];

			attributes.forEach(function (attribute) {
				claims[attribute['@'].Name] = attribute.AttributeValue[0];
			});
		}
	}

	if (assertion.Subject.NameID) {
		claims[nameIdentifierClaimType] = assertion.Subject.NameID;
	}

	return {
		claims: claims,
		issuer: assertion.Issuer
	}
};

saml20.validateAudience = function (assertion, realm) {
	if (Array.isArray(realm)) {
		return realm.indexOf(assertion.Conditions[0].AudienceRestriction[0].Audience[0]) != -1;
	};

  	return assertion.Conditions[0].AudienceRestriction[0].Audience[0] === realm;
};

saml20.validateExpiration = function (assertion) {
 	var notBefore = new Date(assertion.Conditions[0]['@'].NotBefore);
   	notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10);  // 10 minutes clock skew

  	var notOnOrAfter = new Date(assertion.Conditions[0]['@'].NotOnOrAfter);
  	notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10);  // 10 minutes clock skew

  	var now = new Date();
    return !(now < notBefore || now > notOnOrAfter)
 }