package burp;

import nb.burp.cacheplz.CachePlz;

/***********************************************************
 * The main Burp Suite extension class, delegates work off
 * to the nb.burp.cacheplz.CachePlz class.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BurpExtender {
	private CachePlz _cacheplz;
	
	public BurpExtender() {
		_cacheplz = new CachePlz();
	}
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		_cacheplz.initialise(callbacks);
	}
}
