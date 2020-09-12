package nb.burp.cacheplz;

import java.net.URL;

/***********************************************************
 * A class to describe stuff that should be force-cached.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class CacheMePlz {
	private String _pattern;		//String/regex to match
	private boolean _enabled;		//Whether this rule is enabled or not
	private boolean _regexMatch;	//Whether to do a regex match or not
	
	public CacheMePlz() {
		_pattern = "";
		_enabled = true;
		_regexMatch = false;
	}
	
	public void setPattern(String pattern) { _pattern = pattern; }
	public void setEnabled(boolean enabled) { _enabled = enabled; }
	public void setIsRegexMatch(boolean isRegexMatch) { _regexMatch = isRegexMatch; }
	
	public String getPattern() { return _pattern; }
	public boolean isEnabled() { return _enabled; }
	public boolean isRegexMatch() { return _regexMatch; }
	
	/**
	 * Test if this rule matches a URL.
	 * 
	 * @param url The URL to test.
	 * @return True if this rule matches the given URL.
	 */
	public boolean testUrl(URL url) {
		if(_enabled == true) {
			if(_regexMatch == true) {
				return url.toString().matches(_pattern);
			} else {
				return url.toString().equals(_pattern);
			}
		}
		return false;
	}
}
