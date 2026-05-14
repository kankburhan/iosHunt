// ============================================
// Keychain Sharing & Access Control Monitor
// ============================================
// Monitors keychain operations to detect:
// 1. Overpermissive access groups
// 2. Data being shared with other apps
// 3. Insecure access attributes

console.log("[*] Loading Keychain Security Monitor...");

var SecItemAdd = Module.findExportByName(null, "SecItemAdd");
var SecItemCopyMatching = Module.findExportByName(null, "SecItemCopyMatching");
var SecItemUpdate = Module.findExportByName(null, "SecItemUpdate");

var kSecAttrAccessGroup = "agrp";
var kSecAttrAccessible = "pdmn";

// Hook SecItemAdd (Add keychain item)
if (SecItemAdd) {
  Interceptor.attach(SecItemAdd, {
    onEnter: function(args) {
      var query = args[0];

      // query is a CFDictionary - need to extract its contents
      try {
        var queryDict = new ObjC.Object(query);

        // Get access group if set
        var accessGroup = queryDict.objectForKey_(
          ObjC.classes.NSString.$stringWithUTF8String_(kSecAttrAccessGroup)
        );

        var accessible = queryDict.objectForKey_(
          ObjC.classes.NSString.$stringWithUTF8String_(kSecAttrAccessible)
        );

        var service = queryDict.objectForKey_(
          ObjC.classes.NSString.$stringWithUTF8String_("svce")
        );

        if (accessGroup) {
          console.log("\n[KEYCHAIN_ADD] Storing item with custom access group:");
          console.log("  Service: " + (service ? service : "N/A"));
          console.log("  Access Group: " + accessGroup);
          console.log("  Access Level: " + (accessible ? accessible : "default"));

          send({
            type: "keychain_sharing",
            operation: "add",
            accessGroup: accessGroup.toString(),
            service: service ? service.toString() : null,
            severity: accessGroup.toString().indexOf("*") > -1 ? "CRITICAL" : "HIGH"
          });

          // Flag suspicious access groups
          var groupStr = accessGroup.toString();
          if (groupStr.indexOf("*") > -1) {
            console.log("  [!!!] CRITICAL: Wildcard access group - accessible by ANY app!");
          } else if (groupStr.indexOf("group.") > -1) {
            console.log("  [!] WARNING: App group sharing enabled");
          }
        }
      } catch(e) {
        console.log("  [*] Could not parse keychain query: " + e.message);
      }
    }
  });
}

// Hook SecItemCopyMatching (Read keychain item)
if (SecItemCopyMatching) {
  Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
      try {
        var query = new ObjC.Object(args[0]);
        var accessGroup = query.objectForKey_(
          ObjC.classes.NSString.$stringWithUTF8String_(kSecAttrAccessGroup)
        );

        if (accessGroup) {
          console.log("\n[KEYCHAIN_READ] Accessing keychain with group:");
          console.log("  Access Group: " + accessGroup);

          send({
            type: "keychain_read",
            accessGroup: accessGroup.toString()
          });
        }
      } catch(e) {
        // Noop
      }
    }
  });
}

// Hook SecItemUpdate
if (SecItemUpdate) {
  Interceptor.attach(SecItemUpdate, {
    onEnter: function(args) {
      try {
        var query = new ObjC.Object(args[0]);
        var accessGroup = query.objectForKey_(
          ObjC.classes.NSString.$stringWithUTF8String_(kSecAttrAccessGroup)
        );

        if (accessGroup) {
          console.log("\n[KEYCHAIN_UPDATE] Modifying item access:");
          console.log("  Access Group: " + accessGroup);

          send({
            type: "keychain_update",
            accessGroup: accessGroup.toString()
          });
        }
      } catch(e) {
        // Noop
      }
    }
  });
}

// Also hook high-level APIs
try {
  var NSKeychainItem = ObjC.classes.NSKeychainItem;
  var KeychainItemWrapper = ObjC.classes.KeychainItemWrapper;

  // Monitor common keychain wrappers
  if (KeychainItemWrapper) {
    var setObject = KeychainItemWrapper["$-setObject:forKey:"];

    if (setObject) {
      Interceptor.attach(setObject.implementation, {
        onEnter: function(args) {
          var wrapper = new ObjC.Object(args[0]);
          var key = new ObjC.Object(args[3]).toString();

          console.log("[*] Storing keychain item: " + key);

          send({
            type: "keychain_wrapper_store",
            key: key
          });
        }
      });
    }
  }
} catch(e) {
  // Noop
}

// Monitor app groups usage (suggests data sharing)
try {
  var NSFileManager = ObjC.classes.NSFileManager;
  var containerURLForSecurityApplicationGroupIdentifier =
    NSFileManager["$-containerURLForSecurityApplicationGroupIdentifier:"];

  if (containerURLForSecurityApplicationGroupIdentifier) {
    Interceptor.attach(
      containerURLForSecurityApplicationGroupIdentifier.implementation,
      {
        onEnter: function(args) {
          var groupID = new ObjC.Object(args[2]).toString();
          console.log("\n[APP_GROUP] Accessing shared container:");
          console.log("  Group ID: " + groupID);
          console.log("  [!] Data shared with app extensions/other apps!");

          send({
            type: "app_group_access",
            groupID: groupID
          });
        }
      }
    );
  }
} catch(e) {
  // Noop
}

console.log("[+] Keychain Security Monitor loaded");
console.log("[*] Watching for insecure keychain sharing...\n");
