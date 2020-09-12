package nb.burp.cacheplz;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/***********************************************************
 * Burp Suite extension to enforce caching on 
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class CachePlz implements IHttpListener {
	private IBurpExtenderCallbacks _callbacks;
	private IExtensionHelpers _helpers;
	
	//TODO: Probably want a nice fancy pants GUI to configure all this, maybe save and load it.
	private boolean _autoForceCachePlz;
	private ArrayList<String> _cacheExtensionsPlz;
	private long _cacheSizeLimitPlz;
	
	//TODO: Definitely need a GUI to add stuff to this. Will get back to it maybe, Java GUIs are horrendous, give me CreateWindow any day <3. Automagical does the job nicely for now.
	private ArrayList<CacheMePlz> _cacheRules;
	
	/*******************
	 * Initialise the extension
	 ******************/
	public void initialise(IBurpExtenderCallbacks callbacks) {
		_callbacks = callbacks;
		_helpers = _callbacks.getHelpers();
		
		_callbacks.setExtensionName("CachePlz");
		_callbacks.registerHttpListener(this);
		
		//TODO: Save/load settings probably.
		_autoForceCachePlz = true;
		_cacheExtensionsPlz = new ArrayList<String>(Arrays.asList(".js", ".css", ".gif", ".jpg", ".png", ".svg", ".woff", ".woff2"));
		_cacheSizeLimitPlz = 10240;
		_cacheRules = new ArrayList<CacheMePlz>();
	}
	
	/*******************
	 * Check HTTP responses and cache plz where needed.
	 * 
	 * @param toolFlag
	 * @param messageIsRequest
	 * @param messageInfo 
	 ******************/
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		IResponseInfo response;
		byte[] responseBody;
		URL url;
		
		//Only interested in HTTP responses
		if(messageIsRequest == false) {
			//Check the HTTP response code
			responseBody = messageInfo.getResponse();
			response = _helpers.analyzeResponse(responseBody);
			if(response.getStatusCode() == 304) {
				//Got a HTTP 304 Not Modified response, cache plz to stop the badly configured server disabling caching
				doCachePlz(messageInfo, response, responseBody);
			} else if(response.getStatusCode() != 200) {
				//Only cache plz on 200 responses otherwise
				return;
			}
			
			//Grab the requested URL
			url = _helpers.analyzeRequest(messageInfo).getUrl();
			
			//Check if the URL matches any defined caching rules
			for(CacheMePlz rule: _cacheRules) {
				if(rule.testUrl(url) == true) {
					//Cache plz and bail
					doCachePlz(messageInfo, response, responseBody);
					_callbacks.printOutput("CachePlz: " + url);
					return;
				}
			}
			
			//Run auto-caching
			if(_autoForceCachePlz == true) {
				//Check if the file extension of the requested URL matches any of the auto-cached extensions
				for(String ext: _cacheExtensionsPlz) {
					if(url.getFile().toLowerCase().endsWith(ext) == true) {
						//Match, cache plz if the response length is equal to or greater than the threshold
						if(responseBody.length >= _cacheSizeLimitPlz) {
							doCachePlz(messageInfo, response, responseBody);
							_callbacks.printOutput("CachePlz: " + url);
							return;
						}
					}
				}
			}
		}
	}
	
	/*******************
	 * Cache plz.
	 * 
	 * @param response
	 * @param body 
	 ******************/
	private void doCachePlz(IHttpRequestResponse messageInfo, IResponseInfo response, byte[] body) {
		List<String> headers = response.getHeaders();
		Iterator<String> it = headers.iterator();
		boolean changed = false;
		String header;
		byte[] newBody;
		
		//Iterate over the headers and remove "Cache-Control" and "Pragma: no-cache" headers if they exist
		while(it.hasNext()) {
			header = it.next().toLowerCase();
			if((header.contains("pragma:") && header.contains("no-cache")) || header.contains("cache-control:")) {
				it.remove();
				changed = true;
			}
		}
		
		//Rebuild the HTTP response if headers were changed
		if(changed == true) {
			messageInfo.setResponse(_helpers.buildHttpMessage(headers, Arrays.copyOfRange(body, response.getBodyOffset(), body.length)));
		}
	}
}

/**
 * Todo:
 * -> Make a nice gui'n'that and add context menus so specific URLs can be manually added, maybe.
 */
