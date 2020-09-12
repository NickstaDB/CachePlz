# CachePlz
Burp Suite extension to help stop resource hogs from hogging your resources.

Download pre-built JAR file from here: https://github.com/NickstaDB/CachePlz/releases/download/0.1/CachePlz.jar

Lately I've seen a lot of web applications/servers wrongly responding with anti-caching HTTP response headers such as `Cache-Control: no-cache` and `Pragma: no-cache` whilst simultaneously serving up <strike>more bloatware than you'd get on a Compaq desktop</strike> horrific amounts of JavaScript for that fancy-pants front-end. The net result is a laptop that's constantly trying to take off as Burp Suite and other extensions repeatedly try to churn through 20+ horrendous MBs of JavaScript every single time a page loads. Not to mention the resulting GBs of Burp Suite save state data.

This extension attempts to ease the load by removing `Pragma: no-cache` and `Cache-Control` HTTP response headers whenever large resources are returned (e.g. `.js`, `.css` files, and for good measure some other extensions for static resources), allowing the web browser to take back control of caching. You'll know when a URL is "cached plz" as the URL will be written to the extension's output tab under the main Burp Suite "Extender" tab.

In the event you do need to force a cached resource to be re-loaded, simply force-reload in your browser (Ctrl + F5, usually). Ain't that lovely.

## To-Do ##

- Implement a GUI to manage the settings
- Add a context menu to manually mark URLs to be cached plz
