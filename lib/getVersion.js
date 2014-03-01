module.exports = function(assertion) {
	
	if (assertion['@'].MajorVersion === '1') {
		return '1.1';
	}
		
	if (assertion['@'].Version === '2.0') {
		return '2.0';
	}
		
	return null;
}