// auto_repro_crypto.js
// Confirms weak crypto usage by hooking CommonCrypto APIs.
// Detects MD5, SHA1, DES, ECB mode, and key derivation issues.
// Emits [REPRO_HIT] markers when weak primitives execute.

'use strict';

console.log('[*] auto_repro_crypto.js loaded — hooking CommonCrypto');

// CCCrypt(operation, algorithm, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutSize, dataOutMoved)
// algorithm: 0=AES, 1=DES, 2=3DES, 3=CAST, 4=RC4, 5=RC2, 6=Blowfish
// options:   0x1=ECB

const algoNames = { 0: 'AES', 1: 'DES (WEAK)', 2: '3DES (LEGACY)', 3: 'CAST', 4: 'RC4 (BROKEN)', 5: 'RC2', 6: 'Blowfish' };

try {
    const CCCrypt = Module.findExportByName(null, 'CCCrypt');
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function (args) {
                try {
                    const op = args[0].toInt32();
                    const algo = args[1].toInt32();
                    const opts = args[2].toInt32();
                    const keyLen = args[4].toInt32();
                    const algoName = algoNames[algo] || `unknown(${algo})`;
                    const opName = op === 0 ? 'ENCRYPT' : 'DECRYPT';
                    const ecb = (opts & 0x1) ? ' ECB-MODE-WEAK' : '';
                    const weak = ['DES', 'RC4', '3DES'].some(w => algoName.includes(w));
                    const weakMark = weak || ecb ? ' [!! WEAK]' : '';
                    console.log(`[REPRO_HIT] [CCCrypt] ${opName} ${algoName} keyLen=${keyLen}${ecb}${weakMark}`);
                } catch (e) { }
            }
        });
    }
} catch (e) { console.log('[!] CCCrypt hook failed: ' + e); }

// Hash functions: CC_MD5, CC_SHA1, CC_SHA256...
const hashes = [
    { name: 'CC_MD5', weak: true },
    { name: 'CC_SHA1', weak: true },
    { name: 'CC_MD2', weak: true },
    { name: 'CC_MD4', weak: true },
    { name: 'CC_SHA224', weak: false },
    { name: 'CC_SHA256', weak: false },
];
for (const h of hashes) {
    try {
        const addr = Module.findExportByName(null, h.name);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try {
                    const len = args[1].toInt32();
                    const mark = h.weak ? ' [!! WEAK HASH]' : '';
                    let data = '';
                    if (len < 256) {
                        try { data = args[0].readByteArray(Math.min(len, 64)); data = '0x' + Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join(''); } catch (e) { }
                    }
                    console.log(`[REPRO_HIT] [${h.name}] inputLen=${len}${mark} ${data.slice(0, 100)}`);
                } catch (e) { }
            }
        });
    } catch (e) { }
}

// CCKeyDerivationPBKDF
try {
    const pbkdf = Module.findExportByName(null, 'CCKeyDerivationPBKDF');
    if (pbkdf) {
        Interceptor.attach(pbkdf, {
            onEnter: function (args) {
                try {
                    const passLen = args[2].toInt32();
                    const saltLen = args[4].toInt32();
                    const rounds = args[6].toInt32();
                    const weak = rounds < 10000;
                    const mark = weak ? ' [!! LOW ROUNDS]' : '';
                    console.log(`[REPRO_HIT] [PBKDF2] passLen=${passLen} saltLen=${saltLen} rounds=${rounds}${mark}`);
                } catch (e) { }
            }
        });
    }
} catch (e) { }

// SecRandomCopyBytes — track entropy source usage (good signal)
try {
    const secRand = Module.findExportByName(null, 'SecRandomCopyBytes');
    if (secRand) {
        Interceptor.attach(secRand, {
            onEnter: function (args) {
                console.log(`[REPRO_HIT] [SecRandomCopyBytes] count=${args[1].toInt32()}`);
            }
        });
    }
} catch (e) { }

console.log('[+] Crypto monitor armed. Trigger encryption/hashing/login flows.');
