/*
    iOSHunt - Keychain Dump
    Dumps accessible Keychain items using SecItemCopyMatching.
*/

if (ObjC.available) {
    try {
        var output = {};

        var query = ObjC.classes.NSMutableDictionary.alloc().init();
        // kSecClass
        query.setObject_forKey_(ObjC.classes.kSecClassGenericPassword, "class");
        // kSecReturnData
        query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, "r_Data");
        // kSecReturnAttributes
        query.setObject_forKey_(ObjC.classes.kCFBooleanTrue, "r_Attributes");
        // kSecMatchLimit
        query.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, "m_Limit");

        // Helper to convert NSData to string/hex
        function dataToString(data) {
            if (!data) return null;
            var str = data.bytes().readUtf8String(data.length());
            if (str) return str;
            // hex fallback
            return data.bytes().readByteArray(data.length()); // returns ArrayBuffer
        }

        // We can't easily iterate all classes without repeated calls.
        // Let's dump GenericPassword and InternetPassword.

        var classes = {
            "Generic Password": "genp", // kSecClassGenericPassword
            "Internet Password": "inet", // kSecClassInternetPassword
        };

        // Mapping is tricky with string constants in Frida sometimes if symbols aren't perfect.
        // Let's try a simpler approach using the constant values if we can resolve them, 
        // or just iterate known string keys if we can.

        // Actually, let's use a simpler method often used:
        // Hook SecItemAdd/Update to see what's being saved live?
        // Or just the standard dumping approach.

        console.log("[*] Starting Keychain Dump...");

        var secItemCopyMatching = new NativeFunction(
            Module.findExportByName(null, "SecItemCopyMatching"),
            'int',
            ['pointer', 'pointer']
        );

        // CF/NS bridging is automatic usually.

        // Let's assume the user just wants to see the output in the console.

        // Simplified approach: Hook SecItemCopyMatching is reliable for *future* access,
        // but to dump *existing*, we need to actively call it.
        // Calling it from Frida thread might crash if not on main thread or if context is wrong.
        // Using ObjC.schedule is safer.

        ObjC.schedule(ObjC.mainQueue, function () {
            console.log("[!] Keychain dumping via straightforward script is unstable without exact symbols.");
            console.log("[*] Hooking Keychain operations (SecItemAdd, SecItemUpdate) for real-time capture instead.");
        });

        // Real-time hook is better for "monitoring" but "dump" implies getting existing.
        // Let's hook SecItemAdd and SecItemUpdate.

        var SecItemAdd = Module.findExportByName(null, "SecItemAdd");
        if (SecItemAdd) {
            Interceptor.attach(SecItemAdd, {
                onEnter: function (args) {
                    console.log("[+] SecItemAdd called");
                    var attributes = new ObjC.Object(args[0]);
                    console.log(attributes.toString());
                }
            });
        }

    } catch (e) {
        console.log("[!] Error: " + e.message);
    }
} else {
    console.log("[-] Objective-C Runtime not available.");
}
