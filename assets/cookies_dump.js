/*
    iOSHunt - Cookies Dump
    Dumps sharedHTTPCookieStorage cookies.
*/

if (ObjC.available) {
    var storage = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
    var cookies = storage.cookies();
    var count = cookies.count();

    console.log("[*] Dumping Cookies (" + count + ")...");

    for (var i = 0; i < count; i++) {
        var cookie = cookies.objectAtIndex_(i);
        console.log("  Name: " + cookie.name());
        console.log("    Value: " + cookie.value());
        console.log("    Domain: " + cookie.domain());
        console.log("    Path: " + cookie.path());
        console.log("    Secure: " + cookie.isSecure());
        console.log("    HTTPOnly: " + cookie.isHTTPOnly());
        console.log("");
    }
    console.log("[*] Done.");
}
