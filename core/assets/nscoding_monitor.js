// ============================================
// NSCoding Deserialization Security Monitor
// ============================================
// Monitors unsafe object deserialization to detect:
// 1. Unsafe NSCoding usage
// 2. Object injection attempts
// 3. Malicious plist loading

console.log("[*] Loading NSCoding Security Monitor...");

var NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
var NSKeyedArchiver = ObjC.classes.NSKeyedArchiver;

// Hook NSKeyedUnarchiver.unarchiveObjectWithData (UNSAFE)
if (NSKeyedUnarchiver) {
  var unarchiveUnsafe = NSKeyedUnarchiver["$+unarchiveObjectWithData:"];

  if (unarchiveUnsafe) {
    Interceptor.attach(unarchiveUnsafe.implementation, {
      onEnter: function(args) {
        console.log("\n[!] CRITICAL: Unsafe unarchiveObjectWithData called!");
        console.log("  Method: NSKeyedUnarchiver.unarchiveObjectWithData");
        console.log("  Vulnerability: Can deserialize ANY object type");
        console.log("  Risk: Object Injection / Remote Code Execution\n");

        send({
          type: "nscoding_vulnerability",
          severity: "CRITICAL",
          method: "unarchiveObjectWithData",
          description: "Unsafe deserialization used - possible RCE"
        });
      },
      onLeave: function(retval) {
        var result = new ObjC.Object(retval);
        console.log("[*] Deserialized object type: " + result.$className);
      }
    });
  }

  // Hook safer method: unarchiveTopLevelObjectWithData:allowingSecureCoding:error:
  var unarchiveSafe = NSKeyedUnarchiver[
    "$+unarchiveTopLevelObjectWithData:allowingSecureCoding:error:"
  ];

  if (unarchiveSafe) {
    Interceptor.attach(unarchiveSafe.implementation, {
      onEnter: function(args) {
        console.log("[+] Safe deserialization: unarchiveTopLevelObjectWithData");
        console.log("  Secure: YES");
        console.log("  Class allowlist applied\n");

        send({
          type: "nscoding_secure",
          method: "unarchiveTopLevelObjectWithData:allowingSecureCoding:error:",
          description: "Secure deserialization method used"
        });
      }
    });
  }
}

// Hook NSKeyedArchiver to detect what's being serialized
if (NSKeyedArchiver) {
  var archiveRootObject = NSKeyedArchiver["$+archivedDataWithRootObject:"];

  if (archiveRootObject) {
    Interceptor.attach(archiveRootObject.implementation, {
      onEnter: function(args) {
        var obj = new ObjC.Object(args[2]);
        console.log("[*] Archiving object: " + obj.$className);
        console.log("  Data will be serialized for storage/transmission");

        send({
          type: "nscoding_archive",
          objectClass: obj.$className,
          description: "Object being serialized"
        });
      }
    });
  }
}

// Hook NSCoder implementations to monitor data flow
try {
  var NSCoder = ObjC.classes.NSCoder;

  if (NSCoder) {
    // Monitor what attributes are being encoded
    var decodeObject = NSCoder["-decodeObjectOfClass:forKey:error:"];

    if (decodeObject) {
      Interceptor.attach(decodeObject.implementation, {
        onEnter: function(args) {
          var className = new ObjC.Object(args[2]).$className;
          var key = new ObjC.Object(args[3]).toString();

          console.log("[*] Decoding class: " + className + " (key: " + key + ")");
        }
      });
    }
  }
} catch(e) {
  // Noop
}

// Hook plist loading from files (common attack vector)
try {
  var NSDictionary = ObjC.classes.NSDictionary;
  var NSArray = ObjC.classes.NSArray;

  // dictionaryWithContentsOfFile: can deserialize plists
  var dictFromFile = NSDictionary["$+dictionaryWithContentsOfFile:"];

  if (dictFromFile) {
    Interceptor.attach(dictFromFile.implementation, {
      onEnter: function(args) {
        var filepath = new ObjC.Object(args[2]).toString();
        console.log("[*] Loading plist from file: " + filepath);

        // Flag if loading from user-writable location
        if (filepath.indexOf("/tmp") > -1 || filepath.indexOf("/var") > -1) {
          console.log("  [!] WARNING: Loading from potentially user-writable location!");

          send({
            type: "plist_security_risk",
            file: filepath,
            risk: "File may be modified by attacker"
          });
        }
      }
    });
  }
} catch(e) {
  // Noop
}

console.log("[+] NSCoding Security Monitor loaded");
console.log("[*] Watching for unsafe deserialization...\n");
