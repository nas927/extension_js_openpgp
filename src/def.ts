export interface KeyPair {
    private?: string;
    public?: string;
    revoc?: string;
    passphrase?: string;
}

export interface Inputs {
    name?: string | HTMLInputElement | HTMLElement,
    email?: string | HTMLInputElement | HTMLElement, 
    public?: string | HTMLInputElement | HTMLElement 
}

export interface InputsCheck extends Inputs 
{
    publicK?: string | HTMLInputElement | HTMLElement,
    publicKey?: string | HTMLInputElement | HTMLElement,
    privateK?: string | HTMLInputElement | HTMLElement,
    privateKey?: string | HTMLInputElement | HTMLElement,
    message?: string | HTMLInputElement | HTMLElement,
    seed?: string
}

export enum PGPCurve {
    CURVE25519 = 'curve25519Legacy',    // Default, recommended
    ED25519 = 'ed25519',          // Same as curve25519
    NIST_P256 = 'p256',          // NIST P-256
    NIST_P384 = 'p384',          // NIST P-384
    NIST_P521 = 'p521',          // NIST P-521
    BRAINPOOL_P256 = 'brainpoolP256r1',  // BSI standard
    BRAINPOOL_P384 = 'brainpoolP384r1',  // BSI standard
    BRAINPOOL_P512 = 'brainpoolP512r1',  // BSI standard
    SECP256K1 = 'secp256k1'      // Bitcoin curve
}

export enum keys {
    PUBLIC,
    PRIVATE,
    SIGN
}