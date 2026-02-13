/*
    iOSHunt - NSUserDefaults Dump
    Dumps all keys in standardUserDefaults.
*/

if (ObjC.available) {
    var defaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
    var dict = defaults.dictionaryRepresentation();
    var enumerator = dict.keyEnumerator();
    var key;

    console.log("[*] Dumping NSUserDefaults...");

    while ((key = enumerator.nextObject())) {
        var keyStr = key.toString();
        // Filter system keys
        if (keyStr.startsWith("NS") || keyStr.startsWith("Apple") || keyStr.startsWith("WebKit")) {
            continue;
        }

        var val = dict.objectForKey_(key);
        console.log("  " + keyStr + ": " + val.toString());
    }
    console.log("[*] Done.");
}
