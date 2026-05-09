// auto_repro_storage.js
// Confirms insecure local storage by hooking NSUserDefaults, NSFileManager, fopen.
// Useful for validating "stored in plist", "no encryption" findings.
// Emits [REPRO_HIT] markers.

'use strict';

if (ObjC.available) {
    console.log('[*] auto_repro_storage.js loaded — hooking NSUserDefaults / NSFileManager / fopen');

    // ---- NSUserDefaults set/get ----
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        const setMethods = ['- setObject:forKey:', '- setBool:forKey:', '- setInteger:forKey:'];
        const getMethods = ['- objectForKey:', '- stringForKey:', '- dataForKey:'];

        for (const m of setMethods) {
            if (NSUserDefaults[m]) {
                Interceptor.attach(NSUserDefaults[m].implementation, {
                    onEnter: function (args) {
                        try {
                            const value = new ObjC.Object(args[2]);
                            const key = new ObjC.Object(args[3]);
                            const valStr = value ? value.toString().slice(0, 200) : '<nil>';
                            console.log(`[REPRO_HIT] [NSUserDefaults.${m.trim()}] ${key} = ${valStr}`);
                        } catch (e) { }
                    }
                });
            }
        }
        for (const m of getMethods) {
            if (NSUserDefaults[m]) {
                Interceptor.attach(NSUserDefaults[m].implementation, {
                    onEnter: function (args) {
                        this.key = new ObjC.Object(args[2]).toString();
                    },
                    onLeave: function (retval) {
                        try {
                            const v = new ObjC.Object(retval);
                            if (v) {
                                const s = v.toString().slice(0, 200);
                                console.log(`[REPRO_HIT] [NSUserDefaults.${m.trim()}] ${this.key} -> ${s}`);
                            }
                        } catch (e) { }
                    }
                });
            }
        }
        console.log('[+] hooked NSUserDefaults read/write');
    } catch (e) { console.log('[!] NSUserDefaults hook failed: ' + e); }

    // ---- NSFileManager createFileAtPath:contents:attributes: ----
    try {
        const NSFM = ObjC.classes.NSFileManager;
        if (NSFM['- createFileAtPath:contents:attributes:']) {
            Interceptor.attach(NSFM['- createFileAtPath:contents:attributes:'].implementation, {
                onEnter: function (args) {
                    try {
                        const path = new ObjC.Object(args[2]).toString();
                        const data = new ObjC.Object(args[3]);
                        const len = data ? data.length() : 0;
                        console.log(`[REPRO_HIT] [NSFileManager.create] ${path} (${len} bytes)`);
                    } catch (e) { }
                }
            });
        }
        if (NSFM['- removeItemAtPath:error:']) {
            Interceptor.attach(NSFM['- removeItemAtPath:error:'].implementation, {
                onEnter: function (args) {
                    try {
                        console.log(`[REPRO_HIT] [NSFileManager.remove] ${new ObjC.Object(args[2])}`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    // ---- NSData writeToFile:atomically: ----
    try {
        const NSData = ObjC.classes.NSData;
        if (NSData['- writeToFile:atomically:']) {
            Interceptor.attach(NSData['- writeToFile:atomically:'].implementation, {
                onEnter: function (args) {
                    try {
                        const self = new ObjC.Object(args[0]);
                        const path = new ObjC.Object(args[2]).toString();
                        console.log(`[REPRO_HIT] [NSData.writeToFile] ${path} (${self.length()} bytes)`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    // ---- fopen libc ----
    try {
        const fopenAddr = Module.findExportByName(null, 'fopen');
        if (fopenAddr) {
            Interceptor.attach(fopenAddr, {
                onEnter: function (args) {
                    try {
                        const path = args[0].readUtf8String();
                        const mode = args[1].readUtf8String();
                        if (path && !path.startsWith('/usr/') && !path.startsWith('/System/')) {
                            console.log(`[REPRO_HIT] [fopen] ${mode} ${path}`);
                        }
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    console.log('[+] Storage monitor armed. Trigger save/cache operations.');
} else {
    console.log('[!] ObjC runtime not available');
}
