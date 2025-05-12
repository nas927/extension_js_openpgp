import EventEmitter from 'events';
import { InputsCheck } from './def';
import Toastify from 'toastify-js';

export function toast(message: string, background: string = "red") {
    Toastify({
        text: message,
        duration: 3000,
        newWindow: true,
        close: true,
        gravity: "top", // `top` or `bottom`
        position: "right", // `left`, `center` or `right`
        stopOnFocus: true, // Prevents dismissing of toast on hover
        style: {
            //background: "linear-gradient(to right, #00b09b, #96c93d)",
            background: background,
        },
    }).showToast();
}

export function checkAll(show: boolean, args: InputsCheck): boolean {
    let response: boolean;
    const newArgs = Object.keys(args);
    console.log(args);
    newArgs.map((arg) => {
        if (args[arg] === "")
        {
            if (show)
                toast(arg + " is not filled");
            response = true;
        }
    });
    if (response)
        return true;
    return false;
}

export function retrieveNames(localStorage: Storage): string[] {
    let keys = [];

    for (const storage in localStorage)
    {
        if (storage.match(/^[^_]+$/))
            keys.push(storage);
    }
    return keys;
}

export function init(): void {
    const selectEncrypt = document.getElementById("encryptSelect") as HTMLSelectElement;
    const selectDecrypt = document.getElementById("decryptSelect") as HTMLSelectElement;
    const selectSigning = document.getElementById("signingSelect") as HTMLSelectElement;

    let itemsName: string[] = retrieveNames({...localStorage});
    console.log(itemsName);

    if (!selectEncrypt || !selectDecrypt)
        throw new Error("Can't find select");

    itemsName.forEach((item) => {
        const optionEncrypt = document.createElement("option");
        const optionDecrypt = document.createElement("option");
        const optionSigning = document.createElement("option");

        optionEncrypt.innerHTML = item;
        optionDecrypt.innerHTML = item;
        optionSigning.innerHTML = item;

        optionEncrypt.addEventListener("click", (event) => {
            bindValues(event, "encrypt")
        });
        optionDecrypt.addEventListener("click", (event) => {
            bindValues(event, "decrypt")
        });
        optionSigning.addEventListener("click", (event) => {
            bindValues(event, "signer")
        });

        selectEncrypt.appendChild(optionEncrypt)
        selectDecrypt.appendChild(optionDecrypt)
        selectSigning.appendChild(optionSigning);
    });
}

export function bindValues(event, string: string): void {
    const publicKeyEncrypt = document.getElementById("publicKeyToEncrypt") as HTMLInputElement;
    const privateKeyEncrypt = document.getElementById("privateKeyToEncrypt") as HTMLInputElement;
    const passphraseEncrypt = document.getElementById("passPhraseToEncrypt") as HTMLInputElement;

    const publicKeyDecrypt = document.getElementById("publicKeyToDecrypt") as HTMLInputElement;
    const privateKeyDecrypt = document.getElementById("privateKeyToDecrypt") as HTMLInputElement;
    const passphraseDecrypt = document.getElementById("passPhraseToDecrypt") as HTMLInputElement;

    const privateKeySigning = document.getElementById("signingPrivateKey") as HTMLInputElement;
    const passphraseSigning = document.getElementById("signingPassPhrase") as HTMLInputElement;

    const publicKey = localStorage.getItem(event.target.innerText + "_public");
    const privateKey = localStorage.getItem(event.target.innerText + "_private");
    const passphrase = localStorage.getItem(event.target.innerText + "_seedHex");

    if (string === "encrypt")
    {
        if (publicKey !== "")
            publicKeyEncrypt.value = publicKey;
        if (privateKey !== "")
            privateKeyEncrypt.value = privateKey;
        if (passphrase !== "")
            passphraseEncrypt.value = passphrase;
    }
    else if (string === "decrypt")
    {
        if (publicKey !== "")
            publicKeyDecrypt.value = publicKey;
        if (privateKey !== "")
            privateKeyDecrypt.value = privateKey;
        if (passphrase !== "")
            passphraseDecrypt.value = passphrase;
    }
    else if (string === "signer")
    {
        if (privateKey !== "")
            privateKeySigning.value = privateKey;
        if (passphrase !== "")
            passphraseSigning.value = passphrase;
    }
}