import * as openpgp from 'openpgp';
import { Buffer } from 'buffer';
import Key from './key';

globalThis.Buffer = Buffer

openpgp.config.rejectCurves = new Set([]);

const key = new Key();
const generateKey = document.getElementById("generateKey")?.addEventListener("click", () => {
    const name = document.getElementById("newKeyName") as HTMLInputElement;
    const email = document.getElementById("newKeyEmail") as HTMLInputElement;
    
    if (!name || !email) {
        throw new Error("Elements not found");
    }
    key.generateKey(name.value, email.value);
});

const saveKey = document.getElementById("savePublicKey")?.addEventListener("click", () => {
    const name = document.getElementById("saveKeyName") as HTMLInputElement;
    const email = document.getElementById("saveKeyEmail") as HTMLInputElement;
    const publicKey = document.getElementById("saveKeyData") as HTMLInputElement;
    
    if (!name || !email || !publicKey) {
        throw new Error("Elements not found");
    }
    if (!key.verifyKey(0, publicKey.value))
        return;

    key.storeMnemonic(name.value, email.value, "", publicKey.value);
});

const encrypt = document.getElementById("encryptMessage")?.addEventListener("click", async () => {
    const publicKey = document.getElementById("publicKeyToEncrypt") as HTMLInputElement;
    const privateKey = document.getElementById("privateKeyToEncrypt") as HTMLInputElement;
    const passphrase = document.getElementById("passPhraseToEncrypt") as HTMLInputElement;
    const message = document.getElementById("messageToEncrypt") as HTMLInputElement;
    const sign = document.getElementById("sign") as HTMLInputElement;

    if (!publicKey || !message || !privateKey || !passphrase) {
        throw new Error("Elements not found");
    }

    const generated: string | void = await key.encryptOrDecrypt(
        { public: publicKey.value, private: privateKey.value, passphrase: passphrase.value }, 
        message.value, 
        "encrypt",
        sign.checked);

    message.value = generated as string;
});
const decrypt = document.getElementById("decryptMessage")?.addEventListener("click", async () => {
    const publicKey = document.getElementById("publicKeyToDecrypt") as HTMLInputElement;
    const privateKey = document.getElementById("privateKeyToDecrypt") as HTMLInputElement;
    const passphrase = document.getElementById("passPhraseToDecrypt") as HTMLInputElement;
    const message = document.getElementById("messageToDecrypt") as HTMLInputElement;

    if (!publicKey || !message || !privateKey || !passphrase) {
        throw new Error("Elements not found");
    }

    const generated: any | void = await key.encryptOrDecrypt(
        { public: publicKey.value, private: privateKey.value, passphrase: passphrase.value},
        message.value,
        "decrypt"
    );

    message.value = generated as string;
});

const sign = document.getElementById("Signing")?.addEventListener("click", async () => {
    const privateKey = document.getElementById("signingPrivateKey") as HTMLInputElement;
    const passphrase = document.getElementById("signingPassPhrase") as HTMLInputElement;
    const signature = document.getElementById("signingData") as HTMLInputElement;

    if (!privateKey || !signature) {
        throw new Error("Elements not found");
    }

    signature.value = await key.sign({ private: privateKey.value, passphrase: passphrase.value }, signature.value);
});

const checkSign = document.getElementById("verifySignature")?.addEventListener("click", () => {
    const publicKey = document.getElementById("signaturePublicKey") as HTMLInputElement;
    const signature = document.getElementById("signatureData") as HTMLInputElement;

    if (!publicKey || !signature) {
        throw new Error("Elements not found");
    }

    key.verifySign(signature.value, publicKey.value);
});
