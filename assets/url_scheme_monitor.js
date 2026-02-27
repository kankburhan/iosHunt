// ============================================
// URL Scheme Security Monitor
// ============================================
// Hooks into UIApplication URL handling to detect:
// 1. Unsafe deep link handling
// 2. Missing parameter validation
// 3. URL injection attempts

console.log("[*] Loading URL Scheme Monitor...");

// Hook UIApplication.openURL methods
var UIApplication = ObjC.classes.UIApplication;
var NSString = ObjC.classes.NSString;

var openURL = UIApplication["$-application:openURL:options:completionHandler:"];
if (openURL) {
  Interceptor.attach(openURL.implementation, {
    onEnter: function(args) {
      var application = new ObjC.Object(args[0]);
      var url = new ObjC.Object(args[2]);

      console.log("\n[URL_SCHEME] URL Scheme Called:");
      console.log("  Scheme: " + url.$ownMembers()["scheme"]);
      console.log("  Full URL: " + url.$ownMembers()["absoluteString"]);

      // Check for suspicious patterns
      var urlString = url.$ownMembers()["absoluteString"].toString();

      // Pattern 1: SQL injection attempts in URL params
      if (urlString.indexOf("'") > -1 || urlString.indexOf("--") > -1) {
        console.log("  [!] SUSPICIOUS: Possible SQL injection in URL");
        send({
          type: "url_scheme_attack",
          pattern: "sql_injection",
          url: urlString
        });
      }

      // Pattern 2: JavaScript in URL (XSS via deep link)
      if (urlString.indexOf("javascript:") > -1) {
        console.log("  [!] CRITICAL: JavaScript in URL scheme");
        send({
          type: "url_scheme_attack",
          pattern: "javascript_injection",
          url: urlString
        });
      }

      // Pattern 3: Command injection indicators
      if (urlString.indexOf(";") > -1 || urlString.indexOf("|") > -1 || urlString.indexOf("&&") > -1) {
        console.log("  [!] SUSPICIOUS: Command injection indicators in URL");
        send({
          type: "url_scheme_attack",
          pattern: "command_injection",
          url: urlString
        });
      }

      // Pattern 4: Sensitive data in URL
      var sensitivePatterns = [
        "password=", "token=", "api_key=", "secret=",
        "auth=", "session=", "credit_card", "ssn="
      ];

      for (var i = 0; i < sensitivePatterns.length; i++) {
        if (urlString.toLowerCase().indexOf(sensitivePatterns[i]) > -1) {
          console.log("  [!] WARNING: Sensitive data in URL scheme");
          send({
            type: "url_scheme_sensitive_data",
            pattern: sensitivePatterns[i],
            url: urlString.substring(0, 100) // Don't exfil full sensitive data
          });
        }
      }
    }
  });
}

// Hook custom URL scheme handling
try {
  var UIApplicationDelegate = ObjC.classes.UIApplicationDelegate;

  // Hook application:openURL:sourceApplication:annotation:
  var openURLSourceApp = UIApplicationDelegate[
    "-application:openURL:sourceApplication:annotation:"
  ];

  if (openURLSourceApp) {
    Interceptor.attach(openURLSourceApp.implementation, {
      onEnter: function(args) {
        var url = new ObjC.Object(args[2]);
        var source = new ObjC.Object(args[3]);

        console.log("\n[URL_SCHEME] Legacy URL Handler:");
        console.log("  URL: " + url);
        console.log("  Source: " + source);
        console.log("  [!] WARNING: Using deprecated URL handler");
      }
    });
  }
} catch(e) {
  // Noop
}

console.log("[+] URL Scheme Monitor loaded successfully");
console.log("[*] Watching for URL scheme exploitation attempts...\n");
