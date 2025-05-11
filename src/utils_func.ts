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