// auto_repro_network.js
// Captures all outbound HTTP(S) traffic to confirm endpoint usage / API key transmission.
// Emits [REPRO_HIT] for each URL request observed.
// Works on non-JB devices via FridaGadget injection.

'use strict';

if (ObjC.available) {
    console.log('[*] auto_repro_network.js loaded — monitoring NSURLSession & NSURLConnection');

    // ---- NSURLSession dataTaskWithRequest:completionHandler: ----
    try {
        const NSURLSession = ObjC.classes.NSURLSession;
        const dataTaskSel = 'dataTaskWithRequest:completionHandler:';
        if (NSURLSession[`- ${dataTaskSel}`]) {
            Interceptor.attach(NSURLSession[`- ${dataTaskSel}`].implementation, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        const url = req.URL().absoluteString().toString();
                        const method = req.HTTPMethod() ? req.HTTPMethod().toString() : 'GET';
                        const headers = req.allHTTPHeaderFields();
                        let headerStr = '';
                        if (headers) {
                            const enumerator = headers.keyEnumerator();
                            let key;
                            while ((key = enumerator.nextObject()) !== null) {
                                const v = headers.objectForKey_(key).toString();
                                headerStr += `${key}: ${v} | `;
                            }
                        }
                        console.log(`[REPRO_HIT] [NSURLSession.dataTask] ${method} ${url}`);
                        if (headerStr) console.log(`[REPRO_HIT]   headers: ${headerStr}`);
                        // Body
                        if (req.HTTPBody()) {
                            const body = ObjC.classes.NSString.alloc().initWithData_encoding_(req.HTTPBody(), 4);
                            if (body) console.log(`[REPRO_HIT]   body: ${body.toString().slice(0, 500)}`);
                        }
                    } catch (e) {
                        console.log('[!] dataTask hook err: ' + e);
                    }
                }
            });
        }
    } catch (e) { console.log('[!] NSURLSession hook failed: ' + e); }

    // ---- NSURLConnection sendSynchronousRequest:returningResponse:error: (legacy) ----
    try {
        const NSURLConnection = ObjC.classes.NSURLConnection;
        if (NSURLConnection['+ sendSynchronousRequest:returningResponse:error:']) {
            Interceptor.attach(NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'].implementation, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        console.log(`[REPRO_HIT] [NSURLConnection.sync] ${req.URL().absoluteString()}`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    // ---- CFNetwork low-level (CFURLRequest) ----
    try {
        const cfModule = Module.findExportByName(null, 'CFURLRequestSetURL');
        if (cfModule) {
            Interceptor.attach(cfModule, {
                onEnter: function (args) {
                    try {
                        const cfurl = new ObjC.Object(args[1]);
                        if (cfurl) console.log(`[REPRO_HIT] [CFURLRequest] ${cfurl.toString()}`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    // ---- WebKit WKWebView load ----
    try {
        const WKWebView = ObjC.classes.WKWebView;
        if (WKWebView && WKWebView['- loadRequest:']) {
            Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        console.log(`[REPRO_HIT] [WKWebView.loadRequest] ${req.URL().absoluteString()}`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    console.log('[+] Network monitor armed. Trigger app navigation, login, or API calls now.');
} else {
    console.log('[!] ObjC runtime not available');
}
