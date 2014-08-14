module.exports = function(assertion) {
	
	if (assertion['@'].MajorVersion === '1') {
		throw new Error('SAML 1.0 Version is not supported');
	}
		
	if (assertion['@'].Version === '2.0') {
		return '2.0';
	}
		
	return null;
}