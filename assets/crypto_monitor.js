/*
    iOSHunt - Crypto Monitor
    Hooks CommonCrypto and SecKey APIs to dump keys, IVs, and plaintext.
*/

// Hook CCCrypt (Symmetric Encryption)
Interceptor.attach(Module.findExportByName(null, 'CCCrypt'), {
    onEnter: function (args) {
        this.op = args[0].toInt();
        this.alg = args[1].toInt();
        this.options = args[2].toInt();
        this.key = args[3];
        this.keyLength = args[4].toInt();
        this.iv = args[5];
        this.dataIn = args[6];
        this.dataInLength = args[7].toInt();
        this.dataOut = args[8];
        this.dataOutAvailable = args[9].toInt();
        this.dataOutMoved = args[10];

        var opStr = (this.op == 0) ? "Encrypt" : "Decrypt";
        var algStr = "Unknown";
        switch (this.alg) {
            case 0: algStr = "AES"; break;
            case 1: algStr = "DES"; break;
            case 2: algStr = "3DES"; break;
            case 3: algStr = "CAST"; break;
            case 4: algStr = "RC4"; break;
            case 5: algStr = "RC2"; break;
        }

        console.log("\n[+] CCCrypt (" + opStr + " - " + algStr + ")");
        console.log("    Key: " + readBytes(this.key, this.keyLength));
        if (!this.iv.isNull()) {
            console.log("    IV:  " + readBytes(this.iv, 16)); // Assuming block size 16 for AES
        }

        // Log Input Data
        var inLen = this.dataInLength;
        if (inLen > 256) inLen = 256; // truncate
        console.log("    Input (" + this.dataInLength + " bytes):\n" + hexdump(this.dataIn, { length: inLen, ansi: true }));
    },
    onLeave: function (retval) {
        if (retval.toInt() == 0) { // Success
            // We can't reliable read output here easily without knowing exact length written to *dataOutMoved
            // But usually for Encrypt, it's roughly same size.
        }
    }
});


// Helper to read bytes as hex string
function readBytes(ptr, len) {
    if (ptr.isNull()) return "null";
    var buf = ptr.readByteArray(len);
    return bytesToHex(buf);
}

function bytesToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

console.log("[*] Crypto Monitor loaded. Hooking CCCrypt...");
