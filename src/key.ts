import * as openpgp from 'openpgp';
import * as bip39 from 'bip39';
import { KeyPair, Inputs, PGPCurve, keys } from './def';
import * as utils from './utils_func';

interface PGPFunction {
    encrypt: typeof openpgp.encrypt;
    decrypt: typeof openpgp.decrypt;
}

export default class Key {
    private pgpFunctions: PGPFunction = {
        encrypt: openpgp.encrypt,
        decrypt: openpgp.decrypt
    };

    public storeMnemonic(name: Inputs["name"], email: Inputs["email"], mnemonic: string, publicKey: Inputs["public"], privateKey: string = "", seedHex: string = ""): void {
        // Store the mnemonic securely, e.g., in a database or secure storage
        if (utils.checkAll(true, { name: name, publicKey: publicKey }))
            return;
        name = name as string;
        if (localStorage.getItem(name)) 
        {
            localStorage.setItem(name + "_saved", localStorage.getItem(name));
            localStorage.setItem(name + "_email_saved", localStorage.getItem(name + "_email"));
            localStorage.setItem(name + "_public_saved", localStorage.getItem(name + "_public"));
            if (privateKey !== "")
                localStorage.setItem(name + "_private_saved", localStorage.getItem(name + "_private"));
            if (seedHex !== "")
                localStorage.setItem(name + "_seedHex_saved", localStorage.getItem(name + "_seedHex"))
            localStorage.removeItem(name);
        }
        if (mnemonic !== "")
        {
            localStorage.setItem(name, mnemonic);
            console.log(`Storing mnemonic: ${mnemonic}`);
        }
        if (seedHex !== "")
        {
            localStorage.setItem(name + "_seedHex", seedHex);
            console.log(`Storing seed: ${seedHex}`);
        }
        if (email !== "")
            localStorage.setItem(name + "_email", email as string);
        localStorage.setItem(name + "_public", publicKey as string);
        if (privateKey !== "")
            localStorage.setItem(name + "_private", privateKey);

        utils.toast("Saved to localStorage !", "green");
    }
    
    private mnemoToHex(mnemonic: string): string {
        const seedBuffer = bip39.mnemonicToSeedSync(mnemonic);
    
        return seedBuffer.toString('hex');
    }
    
    public async generateKey(name: Inputs["name"], email: Inputs["email"], mnemonic: string | null = null, curve: PGPCurve = PGPCurve.SECP256K1): Promise<KeyPair> {
        if (utils.checkAll(true, { name: name, email: email }))
            return {};
        let seedHex = "";
        if (mnemonic === "" || !mnemonic) {
            mnemonic = bip39.generateMnemonic(); 
            
            const seedBuffer = await bip39.mnemonicToSeed(mnemonic); // returns Buffer
            
            seedHex = seedBuffer.toString('hex');
        }
        else
            seedHex = this.mnemoToHex(mnemonic)
    
        const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
            type: 'ecc', // Type of the key, defaults to ECC
            curve: curve as openpgp.EllipticCurveName,
            userIDs: [{ name: name as string, email: email as string }], // you can pass multiple user IDs
            passphrase: seedHex, // protects the private key
            format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
        });
        
        console.log(seedHex);
        console.log(privateKey);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
        console.log(publicKey);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
        console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
    
        this.storeMnemonic(name, email as string, mnemonic, publicKey, privateKey, seedHex);
    
        return { "private": privateKey, "public": publicKey, "revoc": revocationCertificate, "passphrase": seedHex};
    }
    
    public async encryptOrDecrypt(generateKey: KeyPair, plaintext: string, func: string, sign: boolean = true): Promise<string | void> {
        if (utils.checkAll(true, { message: plaintext }) || (utils.checkAll(false, { publicKey: generateKey.public})
        && utils.checkAll(true, { privateKey: generateKey.private })))
            return;

        const message = await openpgp.createMessage({ text: plaintext });
        let publicKey: openpgp.PublicKey;
        let privateKey: openpgp.PrivateKey;
        let encryptedOrDecrypted: any;

        if (generateKey.private !== "" && this.verifyKey(keys.PRIVATE, generateKey.private))
        {
            if (generateKey.passphrase !== "")
            {
                privateKey = await openpgp.decryptKey({
                    privateKey: await openpgp.readPrivateKey({ armoredKey: generateKey.private }),
                    passphrase: generateKey.passphrase
                });
            }
            else
                utils.toast("Define the seedHex");
        }
        if (generateKey.public !== "" && this.verifyKey(keys.PUBLIC, generateKey.public)
        && !utils.checkAll(true, { publicKey: generateKey.public }))
        {
            publicKey = await openpgp.readKey({ armoredKey: generateKey.public });
        }
        
        if (func === 'encrypt') {
            const message = await openpgp.createMessage({ text: plaintext });
            encryptedOrDecrypted = await this.pgpFunctions.encrypt({
                message,
                encryptionKeys: publicKey,
                signingKeys: sign && privateKey ? privateKey : undefined
            });
        } 
        else {
            // Pour le déchiffrement
            const encryptedMessage = await openpgp.readMessage({
                armoredMessage: plaintext
            });

            encryptedOrDecrypted = await this.pgpFunctions.decrypt({
                message: encryptedMessage,
                decryptionKeys: privateKey,
                verificationKeys: publicKey // optionnel, pour vérifier la signature
            });
        }
        console.log(encryptedOrDecrypted);

        return func === 'decrypt' ? encryptedOrDecrypted?.data : encryptedOrDecrypted;
    }

    public async sign(generateKey: KeyPair, plaintext: string): Promise<string> {
        if (utils.checkAll(true, { privateKey: generateKey.private, message: plaintext })
        || !this.verifyKey(keys.PRIVATE, generateKey.private))
            return;
        if (generateKey.passphrase === "")
            utils.toast("Make sure your private key have not seed if input value doesn't change !", "gold")
        const message = await openpgp.createCleartextMessage({
            text: plaintext
        });

        const privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: generateKey.private }),
            passphrase: generateKey.passphrase
        });
    
        const signed = await openpgp.sign({
            message,
            signingKeys: privateKey, 
        });
    
        console.log(signed);
    
        return signed;
    }
    
    public async verifySign(message: string, publicK: string): Promise<void> {
        if (utils.checkAll(true, { message: message, publicKey: publicK })
        || !this.verifyKey(keys.PUBLIC, publicK) 
        || !this.verifyKey(keys.SIGN, message))
            return;
        const publicKey = await openpgp.readKey({ armoredKey: publicK });
        const signedMessage = await openpgp.readCleartextMessage({
            cleartextMessage: message // parse armored message
        });
    
        const verificationResult = await openpgp.verify({
            message: signedMessage,
            verificationKeys: publicKey
        });

        const { verified, keyID } = verificationResult.signatures[0];
        try {
            await verified;
            console.log('Signée par la clé dont l\'id est : ' + keyID.toHex());
            utils.toast("Signée par la clé: " + keyID.toHex(), "green");
        } catch (e) {
            throw new Error('La signature n\'est pas valide : ' + e.message);
        }
    }

    public verifyKey(type: keys, text: string): boolean {
        if (type === keys.PUBLIC)
        {
            if (text.match(/public/i) === null)     
            {
                utils.toast("It doesnt look like a public key");
                return false;
            }
        } 
        else if (type === keys.PRIVATE) {
            if (text.match(/private/i) === null) 
            {
                utils.toast("It doesnt look like a private key");
                return false;
            }
        }
        else if (type === keys.SIGN)
        {
            if (text.match(/signature/i) === null) 
            {
                utils.toast("It doesnt look like signed !");
                return false;
            }
        }
        return true;
    }
}