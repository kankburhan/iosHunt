// auto_repro_url_scheme.js
// Confirms URL scheme handling by hooking AppDelegate openURL methods.
// Validates deep-link / URL scheme exposure and parameter parsing.
// Emits [REPRO_HIT] markers when URL schemes are processed.

'use strict';

if (ObjC.available) {
    console.log('[*] auto_repro_url_scheme.js loaded — hooking openURL handlers');

    // Find the AppDelegate class dynamically
    function findAppDelegate() {
        try {
            const sharedApp = ObjC.classes.UIApplication.sharedApplication();
            const delegate = sharedApp.delegate();
            if (!delegate) return null;
            return delegate.$class;
        } catch (e) {
            return null;
        }
    }

    function hookSelector(klass, sel) {
        try {
            if (!klass[sel]) return false;
            Interceptor.attach(klass[sel].implementation, {
                onEnter: function (args) {
                    try {
                        // openURL: NSURL is at args[2] for app:openURL:options:
                        // For iOS 13+ app:openURL:options: signature: (id, SEL, UIApplication*, NSURL*, NSDictionary*)
                        let urlArg = null;
                        for (let i = 2; i < 6; i++) {
                            try {
                                const o = new ObjC.Object(args[i]);
                                if (o && o.$className === 'NSURL') {
                                    urlArg = o;
                                    break;
                                }
                            } catch (e) { }
                        }
                        if (urlArg) {
                            const u = urlArg.absoluteString().toString();
                            const scheme = urlArg.scheme() ? urlArg.scheme().toString() : '?';
                            const host = urlArg.host() ? urlArg.host().toString() : '?';
                            const path = urlArg.path() ? urlArg.path().toString() : '?';
                            const query = urlArg.query() ? urlArg.query().toString() : '';
                            console.log(`[REPRO_HIT] [openURL] ${u}`);
                            console.log(`[REPRO_HIT]   scheme=${scheme} host=${host} path=${path} query=${query}`);
                        } else {
                            console.log(`[REPRO_HIT] [openURL] (URL extract failed) sel=${sel}`);
                        }
                    } catch (e) { console.log('[!] openURL log err: ' + e); }
                }
            });
            console.log(`[+] hooked ${klass.$className} ${sel}`);
            return true;
        } catch (e) { return false; }
    }

    const delegateClass = findAppDelegate();
    if (delegateClass) {
        const selectors = [
            '- application:openURL:options:',
            '- application:openURL:sourceApplication:annotation:',
            '- application:handleOpenURL:',
            '- application:continueUserActivity:restorationHandler:',
        ];
        for (const s of selectors) hookSelector(delegateClass, s);
    } else {
        console.log('[!] AppDelegate not found yet — install hook on +sharedApplication');
    }

    // Also hook UIApplication openURL: (outbound — app calling another scheme)
    try {
        const UIApp = ObjC.classes.UIApplication;
        const selOut = '- openURL:options:completionHandler:';
        if (UIApp[selOut]) {
            Interceptor.attach(UIApp[selOut].implementation, {
                onEnter: function (args) {
                    try {
                        const u = new ObjC.Object(args[2]);
                        console.log(`[REPRO_HIT] [UIApp.openURL OUT] ${u.absoluteString()}`);
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    // SceneDelegate for iOS 13+
    try {
        const allClasses = ObjC.classes;
        for (const name in allClasses) {
            if (name.includes('SceneDelegate')) {
                const klass = allClasses[name];
                hookSelector(klass, '- scene:openURLContexts:');
                hookSelector(klass, '- scene:willConnectToSession:options:');
            }
        }
    } catch (e) { }

    console.log('[+] URL scheme monitor armed. Trigger by opening a deep link or external URL.');
    console.log('[+] Test from another app: UIApplication.shared.open(URL(string: "<scheme>://...")!)');
} else {
    console.log('[!] ObjC runtime not available');
}
