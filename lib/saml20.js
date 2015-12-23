'use strict';

var nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
var _ = require('lodash');
var saml20 = module.exports;

function getClaims(attributes) {
  var claims = {};

  attributes.forEach(function attributesForEach(attribute) {
    var attributeName = attribute['@'].Name;

    claims[attributeName] = getProp(attribute, 'AttributeValue');
  });

  return claims;
}

function trimWords(phrase) {
  return phrase.split(' ')
  .map(function wordMapping(w) {
    return w.trim();
  })
  .filter(function wordFiltering(w) {
    return !!w;
  })
  .join(' ');
}

function getProp(obj, prop) {
  var result = prop ? _.get(obj, prop) : obj;

  if (result && result._) {
    result = result._;
  }

  if (typeof result === 'string') {
    result = trimWords(result);

    return result;
  }
  else if (result instanceof Array) {
    result.forEach(function parseArrayItem(i, ix) {
      result[ix] = getProp(i);
    });

    return result;
  }
  else {
    return;
  }
}

saml20.parse = function parse(assertion) {
  var claims = {};
  var attributes = _.get(assertion, 'AttributeStatement.Attribute');

  if (attributes) {
    attributes = (attributes instanceof Array) ? attributes : [attributes];
    claims = getClaims(attributes);
  }

  var subjectName = getProp(assertion, 'Subject.NameID');

  if (subjectName) {
    claims[nameIdentifierClaimType] = subjectName;
  }

  return {
    audience: getProp(assertion, 'Conditions.AudienceRestriction.Audience'),
    claims: claims,
    issuer: getProp(assertion, 'Issuer'),
    sessionIndex: getProp(assertion, 'AuthnStatement.@.SessionIndex')
  };
};

saml20.validateAudience = function validateAudience(assertion, realm) {
  var audience = getProp(assertion, 'Conditions.AudienceRestriction.Audience');

  if (Array.isArray(realm)) {
    return realm.indexOf(audience) !== -1;
  }

  return audience === realm;
};

saml20.validateExpiration = function validateExpiration(assertion) {
  var dteNotBefore = getProp(assertion, 'Conditions.@.NotBefore');
  var notBefore = new Date(dteNotBefore);
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew

  var dteNotOnOrAfter = getProp(assertion, 'Conditions.@.NotOnOrAfter');
  var notOnOrAfter = new Date(dteNotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

  var now = new Date();
  return !(now < notBefore || now > notOnOrAfter);
};
