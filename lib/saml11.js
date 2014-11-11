var saml11 = module.exports;

saml11.parse = function (assertion) {
	var claims = {};

	if (assertion.AttributeStatement && assertion.AttributeStatement.length > 0) {
		var attributeStament = assertion.AttributeStatement[0];

		var attributes = attributeStament.Attribute;

		if (attributes) {
			attributes  = (attributes instanceof Array) ? attributes : [attributes];

			attributes.forEach(function (attribute) {
				var attributeName = attribute['@'].AttributeNamespace + '/' + attribute['@'].AttributeName;

				if (attribute.AttributeValue.length == 1) {
					claims[attributeName] = attribute.AttributeValue[0];
				} else {
					claims[attributeName] = attribute.AttributeValue;
				}
			});
		}

		if (attributeStament.Subject && attributeStament.Subject.length > 0 && attributeStament.Subject[0].NameIdentifier) {
			claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = attributeStament.Subject[0].NameIdentifier;
		}
	};

	return {
		claims: claims,
		issuer: assertion['@'].Issuer
	}
}

saml11.validateAudience = function(assertion, realm) {	
	if (Array.isArray(realm)) {
		return realm.indexOf(assertion.Conditions[0].AudienceRestrictionCondition[0].Audience[0]) != -1;
	};

  	return assertion.Conditions[0].AudienceRestrictionCondition[0].Audience[0] === realm;
}

saml11.validateExpiration = function (assertion) {
 	var notBefore = new Date(assertion.Conditions[0]['@'].NotBefore);
   	notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10);  // 10 minutes clock skew

  	var notOnOrAfter = new Date(assertion.Conditions[0]['@'].NotOnOrAfter);
  	notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10);  // 10 minutes clock skew

  	var now = new Date();

    return !(now < notBefore || now > notOnOrAfter)
 }
