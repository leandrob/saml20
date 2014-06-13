var nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

var saml20 = module.exports;
var _ = require('lodash');

saml20.parse = function (assertion) {

  var claims = {};

  if (assertion.AttributeStatement
    || (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:AttributeStatement'])) {

    var attributes;
    if (assertion.AttributeStatement && assertion.AttributeStatement.Attribute) {
      attributes = assertion.AttributeStatement.Attribute;
    } else if (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:AttributeStatement'] && assertion['saml:Assertion']['saml:AttributeStatement']['saml:Attribute']) {
      attributes = assertion['saml:Assertion']['saml:AttributeStatement']['saml:Attribute'];
    }

    if (attributes) {
      attributes = (attributes instanceof Array) ? attributes : [attributes];
      attributes.forEach(function (attribute) {
        claims[attribute['@'].Name] = attribute.AttributeValue || attribute['saml:AttributeValue'];
      });
    }
  }

  if (assertion.Subject && assertion.Subject.NameID) {
    claims[nameIdentifierClaimType] = assertion.Subject.NameID;
  } else if (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:Subject'] && assertion['saml:Assertion']['saml:Subject']['NameID']) {
    claims[nameIdentifierClaimType] = assertion['saml:Assertion']['saml:Subject']['NameID'];
  }

  return {
    claims : claims,
    issuer : assertion.Issuer
      || (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:Issuer']
        ? assertion['saml:Assertion']['saml:Issuer']
        : undefined)
  }
};

saml20.validateAudience = function (assertion, realm) {
  return (assertion.Conditions && assertion.Conditions.AudienceRestriction && assertion.Conditions.AudienceRestriction.Audience && assertion.Conditions.AudienceRestriction.Audience === realm)
    || (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:Conditions'] && assertion['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction'] && assertion['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction']['saml:Audience'] && assertion['saml:Assertion']['saml:Conditions']['saml:AudienceRestriction']['saml:Audience'] === realm);
};

saml20.validateExpiration = function (assertion) {

  var dteNotBefore = (assertion.Conditions && assertion.Conditions['@'] && assertion.Conditions['@'].NotBefore
    ? assertion.Conditions['@'].NotBefore
    : (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:Conditions'] && assertion['saml:Assertion']['saml:Conditions']['@'] && assertion['saml:Assertion']['saml:Conditions']['@']['NotBefore']
    ? assertion['saml:Assertion']['saml:Conditions']['@']['NotBefore']
    : undefined));
  var notBefore = new Date(dteNotBefore);
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10);  // 10 minutes clock skew


  var dteNotOnOrAfter = (assertion.Conditions && assertion.Conditions['@'] && assertion.Conditions['@'].NotOnOrAfter
    ? assertion.Conditions['@'].NotOnOrAfter
    : (assertion['saml:Assertion'] && assertion['saml:Assertion']['saml:Conditions'] && assertion['saml:Assertion']['saml:Conditions']['@'] && assertion['saml:Assertion']['saml:Conditions']['@']['NotOnOrAfter']
    ? assertion['saml:Assertion']['saml:Conditions']['@']['NotOnOrAfter']
    : undefined));
  var notOnOrAfter = new Date(dteNotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10);  // 10 minutes clock skew

  var now = new Date();
  return !(now < notBefore || now > notOnOrAfter)
};