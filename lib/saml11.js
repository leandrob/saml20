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
					claims[attributeName] = attribute.AttributeValue[0]['_'] || attribute.AttributeValue[0];
				} else {
					claims[attributeName] = attribute.AttributeValue.map(function(v) {
						return v['_'] || v;
					});
				}
			});
		}

		if (attributeStament.Subject && attributeStament.Subject.length > 0 && attributeStament.Subject[0].NameIdentifier && attributeStament.Subject[0].NameIdentifier.length > 0) {
			claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = attributeStament.Subject[0].NameIdentifier[0]['_'];
		}
	}

	return {
		claims: claims,
		issuer: assertion['@'].Issuer,
		audience: getAudience(assertion)
	};
};

saml11.validateAudience = function (assertion, realm) {
	var audience = getAudience(assertion);

	if (Array.isArray(realm)) {
		return realm.indexOf(audience) != -1;
	}

	return audience === realm;
};

saml11.validateExpiration = function (assertion) {
 	var notBefore = new Date(assertion.Conditions[0]['@'].NotBefore);
   	notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10);  // 10 minutes clock skew

  	var notOnOrAfter = new Date(assertion.Conditions[0]['@'].NotOnOrAfter);
  	notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10);  // 10 minutes clock skew

  	var now = new Date();

    return !(now < notBefore || now > notOnOrAfter)
 };

 function getAudience(assertion) {
	 if (assertion.Conditions[0] && assertion.Conditions[0].AudienceRestrictionCondition[0]) {
		 return assertion.Conditions[0].AudienceRestrictionCondition[0].Audience[0];
	 } else {
		 return undefined;
	 }
 }
