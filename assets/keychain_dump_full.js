// iOSHunt - Full Keychain Dump & Monitor for AdaKami
// Hooks SecItemAdd, SecItemCopyMatching, SecItemUpdate, SecItemDelete
// Extracts: account, service, data, accessibility, access group

'use strict';

var kSecClass              = ObjC.classes.NSString.stringWithString_("class");
var kSecAttrAccount        = ObjC.classes.NSString.stringWithString_("acct");
var kSecAttrService        = ObjC.classes.NSString.stringWithString_("svce");
var kSecAttrAccessible     = ObjC.classes.NSString.stringWithString_("pdmn");
var kSecAttrAccessGroup    = ObjC.classes.NSString.stringWithString_("agrp");
var kSecValueData          = ObjC.classes.NSString.stringWithString_("v_Data");
var kSecReturnData         = ObjC.classes.NSString.stringWithString_("r_Data");
var kSecReturnAttributes   = ObjC.classes.NSString.stringWithString_("r_Attributes");
var kSecMatchLimit         = ObjC.classes.NSString.stringWithString_("m_Limit");
var kSecMatchLimitAll      = ObjC.classes.NSString.stringWithString_("m_LimitAll");
var kSecAttrLabel          = ObjC.classes.NSString.stringWithString_("labl");

// Accessibility constants mapping
var accessibilityMap = {
    "ak":    "kSecAttrAccessibleWhenUnlocked",
    "ck":    "kSecAttrAccessibleAfterFirstUnlock",
    "dk":    "kSecAttrAccessibleAlways ⚠️ INSECURE",
    "aku":   "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "cku":   "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    "dku":   "kSecAttrAccessibleAlwaysThisDeviceOnly ⚠️ INSECURE",
    "akpu":  "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
};

// Class constants
var classMap = {
    "genp": "kSecClassGenericPassword",
    "inet": "kSecClassInternetPassword",
    "cert": "kSecClassCertificate",
    "keys": "kSecClassKey",
    "idnt": "kSecClassIdentity",
};

function dictToObj(nsDict) {
    if (!nsDict || nsDict.isNull()) return null;
    var dict = new ObjC.Object(nsDict);
    var result = {};
    var keys = dict.allKeys();
    for (var i = 0; i < keys.count(); i++) {
        var key = keys.objectAtIndex_(i).toString();
        var val = dict.objectForKey_(keys.objectAtIndex_(i));
        if (val) {
            var className = val.$className;
            if (className === "NSData" || className === "__NSCFData" || className === "NSConcreteMutableData") {
                // Try to decode as UTF-8 string
                var nsStr = ObjC.classes.NSString.alloc().initWithData_encoding_(val, 4); // NSUTF8StringEncoding
                if (nsStr) {
                    result[key] = nsStr.toString();
                } else {
                    result[key] = "<binary:" + val.length() + " bytes>";
                }
            } else {
                result[key] = val.toString();
            }
        }
    }
    return result;
}

function formatKeychainItem(item) {
    var lines = [];

    if (item["svce"]) lines.push("  Service:       " + item["svce"]);
    if (item["acct"]) lines.push("  Account:       " + item["acct"]);
    if (item["labl"]) lines.push("  Label:         " + item["labl"]);
    if (item["agrp"]) lines.push("  Access Group:  " + item["agrp"]);

    var accessible = item["pdmn"];
    if (accessible) {
        var mapped = accessibilityMap[accessible] || accessible;
        lines.push("  Accessible:    " + mapped);
    }

    var itemClass = item["class"];
    if (itemClass) {
        var mappedClass = classMap[itemClass] || itemClass;
        lines.push("  Class:         " + mappedClass);
    }

    if (item["v_Data"]) {
        var data = item["v_Data"];
        if (data.length > 200) data = data.substring(0, 200) + "...";
        lines.push("  Data:          " + data);
    }

    // Highlight insecure items
    if (accessible === "dk" || accessible === "dku") {
        lines.push("  ⚠️  VULNERABILITY: Accessible while device is LOCKED!");
    }

    return lines.join("\n");
}

// ─── 1. DUMP ALL EXISTING KEYCHAIN ITEMS ─────────────────────────────────────

console.log("\n" + "═".repeat(60));
console.log("  iOSHunt Keychain Dump - AdaKami (com.adakami.loan)");
console.log("═".repeat(60));

function dumpKeychainClass(secClass, className) {
    var query = ObjC.classes.NSMutableDictionary.alloc().init();
    query.setObject_forKey_(ObjC.classes.NSString.stringWithString_(secClass), kSecClass);
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), kSecReturnData);
    query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), kSecReturnAttributes);
    query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);

    var resultPtr = Memory.alloc(Process.pointerSize);
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName(null, "SecItemCopyMatching"),
        "int", ["pointer", "pointer"]
    );

    var status = SecItemCopyMatching(query.handle, resultPtr);

    if (status === 0) { // errSecSuccess
        var results = new ObjC.Object(resultPtr.readPointer());
        var count = results.count();

        console.log("\n┌─ " + className + " (" + count + " items)");
        console.log("│");

        for (var i = 0; i < count; i++) {
            var item = dictToObj(results.objectAtIndex_(i));
            if (item) {
                console.log("├── Item " + (i + 1) + ":");
                console.log(formatKeychainItem(item));
                console.log("│");
            }
        }
        console.log("└─────────────────────────────────────");
        return count;
    } else if (status === -25300) {
        console.log("\n[*] " + className + ": No items found");
        return 0;
    } else {
        console.log("\n[!] " + className + ": Query failed (status: " + status + ")");
        return 0;
    }
}

var totalItems = 0;
totalItems += dumpKeychainClass("genp", "Generic Passwords");
totalItems += dumpKeychainClass("inet", "Internet Passwords");
totalItems += dumpKeychainClass("cert", "Certificates");
totalItems += dumpKeychainClass("keys", "Cryptographic Keys");

console.log("\n[*] Total keychain items dumped: " + totalItems);

// ─── 2. REAL-TIME KEYCHAIN MONITORING ─────────────────────────────────────────

console.log("\n" + "═".repeat(60));
console.log("  Real-time Keychain Monitor (live)");
console.log("═".repeat(60));

// Hook SecItemAdd
var SecItemAdd = Module.findExportByName(null, "SecItemAdd");
if (SecItemAdd) {
    Interceptor.attach(SecItemAdd, {
        onEnter: function(args) {
            this.query = new ObjC.Object(args[0]);
            var item = dictToObj(this.query);

            console.log("\n🔴 [SecItemAdd] New keychain item stored:");
            if (item) console.log(formatKeychainItem(item));

            // Check for insecure accessibility
            if (item && (item["pdmn"] === "dk" || item["pdmn"] === "dku")) {
                console.log("  ⚠️  CRITICAL: Item stored with AccessibleAlways!");
                console.log("  ⚠️  Exploitable: Extract without device unlock");
            }
        },
        onLeave: function(retval) {
            var status = retval.toInt32();
            if (status === 0) {
                console.log("  ✅ Status: Success (stored)");
            } else if (status === -25299) {
                console.log("  ⚠️  Status: Duplicate item");
            } else {
                console.log("  ❌ Status: Failed (" + status + ")");
            }
        }
    });
    console.log("[*] Hooked SecItemAdd");
}

// Hook SecItemCopyMatching
var SecItemCopyMatchingPtr = Module.findExportByName(null, "SecItemCopyMatching");
if (SecItemCopyMatchingPtr) {
    Interceptor.attach(SecItemCopyMatchingPtr, {
        onEnter: function(args) {
            this.query = new ObjC.Object(args[0]);
            this.resultPtr = args[1];
            var item = dictToObj(this.query);

            console.log("\n🔵 [SecItemCopyMatching] Keychain query:");
            if (item) {
                if (item["svce"]) console.log("  Service: " + item["svce"]);
                if (item["acct"]) console.log("  Account: " + item["acct"]);
                if (item["agrp"]) console.log("  Group:   " + item["agrp"]);
            }
        },
        onLeave: function(retval) {
            var status = retval.toInt32();
            if (status === 0 && this.resultPtr) {
                try {
                    var result = new ObjC.Object(this.resultPtr.readPointer());
                    if (result.$className === "NSDictionary" || result.$className === "__NSDictionaryI" || result.$className === "__NSSingleEntryDictionaryI") {
                        var item = dictToObj(result);
                        if (item && item["v_Data"]) {
                            console.log("  📦 Data returned: " + item["v_Data"].substring(0, 100));
                        }
                    } else if (result.$className === "NSData" || result.$className === "__NSCFData") {
                        var nsStr = ObjC.classes.NSString.alloc().initWithData_encoding_(result, 4);
                        if (nsStr) {
                            console.log("  📦 Data: " + nsStr.toString().substring(0, 100));
                        } else {
                            console.log("  📦 Data: <binary:" + result.length() + " bytes>");
                        }
                    }
                } catch(e) {}
            } else if (status === -25300) {
                console.log("  ❌ Not found");
            }
        }
    });
    console.log("[*] Hooked SecItemCopyMatching");
}

// Hook SecItemUpdate
var SecItemUpdate = Module.findExportByName(null, "SecItemUpdate");
if (SecItemUpdate) {
    Interceptor.attach(SecItemUpdate, {
        onEnter: function(args) {
            var query = dictToObj(new ObjC.Object(args[0]));
            var attrs = dictToObj(new ObjC.Object(args[1]));

            console.log("\n🟡 [SecItemUpdate] Keychain item updated:");
            if (query) {
                if (query["svce"]) console.log("  Service: " + query["svce"]);
                if (query["acct"]) console.log("  Account: " + query["acct"]);
            }
            if (attrs && attrs["v_Data"]) {
                console.log("  New Data: " + attrs["v_Data"].substring(0, 100));
            }
        },
        onLeave: function(retval) {
            console.log("  Status: " + (retval.toInt32() === 0 ? "✅ Updated" : "❌ Failed"));
        }
    });
    console.log("[*] Hooked SecItemUpdate");
}

// Hook SecItemDelete
var SecItemDelete = Module.findExportByName(null, "SecItemDelete");
if (SecItemDelete) {
    Interceptor.attach(SecItemDelete, {
        onEnter: function(args) {
            var query = dictToObj(new ObjC.Object(args[0]));
            console.log("\n🗑️  [SecItemDelete] Keychain item deleted:");
            if (query) {
                if (query["svce"]) console.log("  Service: " + query["svce"]);
                if (query["acct"]) console.log("  Account: " + query["acct"]);
            }
        }
    });
    console.log("[*] Hooked SecItemDelete");
}

console.log("\n[*] Keychain monitoring active. Interact with the app to capture operations...\n");
