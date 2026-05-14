/*
    iOSHunt - Header Logger
    Intercepts NSURLRequest/NSMutableURLRequest to capture headers.
*/

if (ObjC.available) {
    // Hook NSMutableURLRequest setValue:forHTTPHeaderField:
    var hook1 = ObjC.classes.NSMutableURLRequest["- setValue:forHTTPHeaderField:"];
    Interceptor.attach(hook1.implementation, {
        onEnter: function (args) {
            var value = ObjC.Object(args[2]).toString();
            var field = ObjC.Object(args[3]).toString();

            // Filter interesting headers or log all?
            if (field.toLowerCase() === "authorization" ||
                field.toLowerCase() === "cookie" ||
                field.toLowerCase().indexOf("token") !== -1) {
                console.log("[*] Header Captured: " + field + ": " + value);
            }
        }
    });

    // Hook allHTTPHeaderFields getter?
    // Might be noisy if called often by framework. 
    // Usually hooking the setter is better for outgoing.

    console.log("[*] Header Logger loaded. Monitoring Authorization/Cookie/Token headers...");
} else {
    console.log("[-] Objective-C Runtime not available.");
}
