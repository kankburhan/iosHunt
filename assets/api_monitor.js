/*
    API Monitor
    Hooks NSURLSession/NSURLConnection to log HTTP requests.
*/

if (ObjC.available) {
    try {
        console.log("[*] API Monitor loaded");

        // Helper to convert NSData to string
        function nsDataToString(data) {
            if (!data) return "(null)";
            var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4); // UTF8
            if (str) return str.toString();
            return "(binary data)";
        }

        // Hook NSURLSession dataTaskWithRequest:completionHandler:
        var className = "NSURLSession";
        var funcName = "- dataTaskWithRequest:completionHandler:";
        var hook = ObjC.classes[className][funcName];

        Interceptor.attach(hook.implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();
                var headers = request.allHTTPHeaderFields() ? request.allHTTPHeaderFields().toString() : "";
                var body = request.HTTPBody();

                console.log("\n================ [API REQUEST] ================");
                console.log("URL    : " + url);
                console.log("Method : " + method);
                console.log("Headers: " + headers.replace(/\n/g, "\n         "));
                if (body) {
                    console.log("Body   : " + nsDataToString(body));
                }
                console.log("===============================================\n");
            }
        });

        console.log("[+] Hooks installed for NSURLSession");

    } catch (e) {
        console.log("[!] Error in API Monitor: " + e.message);
    }
}
