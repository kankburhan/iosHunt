// auto_repro_keychain.js
// Hooks Security framework Keychain access to confirm credential storage / retrieval.
// Logs SecItemAdd, SecItemCopyMatching, SecItemUpdate, SecItemDelete.
// Emits [REPRO_HIT] markers.

'use strict';

if (ObjC.available) {
    console.log('[*] auto_repro_keychain.js loaded — hooking Security.framework');

    function describeQuery(qPtr) {
        try {
            const dict = new ObjC.Object(qPtr);
            const out = {};
            const keys = ['kSecClass', 'kSecAttrService', 'kSecAttrAccount', 'kSecAttrAccessGroup', 'kSecAttrAccessible'];
            for (const k of keys) {
                try {
                    const sym = ObjC.classes.NSString.stringWithString_(k);
                    const v = dict.objectForKey_(sym);
                    if (v) out[k] = v.toString();
                } catch (e) { }
            }
            // Also capture full description for completeness
            return JSON.stringify(out) + ' || ' + dict.toString().slice(0, 400);
        } catch (e) {
            return '<unparseable>';
        }
    }

    const fns = ['SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate', 'SecItemDelete'];
    for (const fn of fns) {
        const addr = Module.findExportByName('Security', fn);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.fn = fn;
                this.queryDesc = describeQuery(args[0]);
            },
            onLeave: function (retval) {
                const status = retval.toInt32();
                console.log(`[REPRO_HIT] [Keychain.${this.fn}] status=${status} query=${this.queryDesc}`);
                // Try to dump returned data for SecItemCopyMatching
                if (this.fn === 'SecItemCopyMatching' && status === 0) {
                    // Result is in args[1] which is **CFTypeRef
                    try {
                        // We didn't save args, but the query may include the data inline
                        console.log('[REPRO_HIT]   ↳ CONFIRMED: keychain item present');
                    } catch (e) { }
                }
            }
        });
        console.log(`[+] hooked Security.${fn}`);
    }

    console.log('[+] Keychain monitor armed. Trigger login, password save, or account ops.');
} else {
    console.log('[!] ObjC runtime not available');
}
