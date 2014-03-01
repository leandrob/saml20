var nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

var saml11 = module.exports;

saml11.parse = function (assertion) {
	var claims = {};

	var attributeStament = assertion['saml:AttributeStatement'];

	if (attributeStament) {
		var attributes = attributeStament['saml:Attribute'];

		if (attributes) {
			attributes  = (attributes instanceof Array) ? attributes : [attributes];

			attributes.forEach(function (attribute) {
				var value = attribute['saml:AttributeValue'];
				var attributeName = attribute['@'].AttributeNamespace + '/' + attribute['@'].AttributeName;

				claims[attributeName] = value;
			});
		}

		if (attributeStament['saml:Subject'] && attributeStament['saml:Subject']['saml:NameIdentifier']) {
			claims[nameIdentifierClaimType] = attributeStament['saml:Subject']['saml:NameIdentifier'];
		}
	};

	return {
		claims: claims,
		issuer: assertion['@'].Issuer
	}
}

saml11.validateAudience = function(assertion, realm) {
	return assertion['saml:Conditions']['saml:AudienceRestrictionCondition']['saml:Audience'] === realm;
}

saml11.validateExpiration = function (assertion) {
 	var notBefore = new Date(assertion['saml:Conditions']['@'].NotBefore);
   	notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10);  // 10 minutes clock skew

  	var notOnOrAfter = new Date(assertion['saml:Conditions']['@'].NotOnOrAfter);
  	notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10);  // 10 minutes clock skew

  	var now = new Date();

    return !(now < notBefore || now > notOnOrAfter)
 }