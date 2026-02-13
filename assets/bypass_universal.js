/*
    iOSHunt - Universal Bypass
    Bypasses Jailbreak detection, Anti-Debugging, and File Integrity checks.
*/

// 1. Bypass ptrace (Anti-Debug)
var ptrace = Module.findExportByName(null, "ptrace");
if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
        if (request == 31) { // PT_DENY_ATTACH
            console.log("[+] Bypassed ptrace(PT_DENY_ATTACH)");
            return 0;
        }
        return 0; // standard ptrace result, might need actual syscall for others
    }, 'int', ['int', 'int', 'pointer', 'int']));
}

// 2. Bypass sysctl (Anti-Debug: kern.proc.pid)
// Not implemented fully via Interceptor.replace as it is complex struct, 
// usually easier to just return 0 or hook higher level logic.

// 3. File System Bypass (Jailbreak Detection)
var badPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt",
    "Cydia"
];

// Hook access / faccessat / stat / lstat / fopen
var access = Module.findExportByName(null, "access");
if (access) {
    Interceptor.attach(access, {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function (retval) {
            for (var i = 0; i < badPaths.length; i++) {
                if (this.path.indexOf(badPaths[i]) >= 0) {
                    console.log("[+] Bypassing jailbreak check for: " + this.path);
                    retval.replace(-1); // Return -1 (error) aka "File not found"
                    return;
                }
            }
        }
    });
}

// Hook stat
var stat = Module.findExportByName(null, "stat");
if (stat) {
    Interceptor.attach(stat, {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function (retval) {
            for (var i = 0; i < badPaths.length; i++) {
                if (this.path && this.path.indexOf(badPaths[i]) >= 0) {
                    // console.log("[+] Bypassing stat check for: " + this.path);
                    retval.replace(-1);
                    return;
                }
            }
        }
    });
}

// Hook fopen
var fopen = Module.findExportByName(null, "fopen");
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
        },
        onLeave: function (retval) {
            for (var i = 0; i < badPaths.length; i++) {
                if (this.path && this.path.indexOf(badPaths[i]) >= 0) {
                    console.log("[+] Bypassing fopen check for: " + this.path);
                    retval.replace(ptr(0)); // Return NULL
                    return;
                }
            }
        }
    });
}

console.log("[*] Universal Bypass loaded (Ptrace + FileSystem).");
