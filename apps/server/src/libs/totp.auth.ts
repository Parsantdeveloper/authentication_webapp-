
import * as OTPAuth from "otpauth";


export  function generateSecret(){
const secret = new OTPAuth.Secret(); 
return secret;
}

export function generateTOTP(email:string,secret:any){
    try{
    const totp = new OTPAuth.TOTP({
    issuer: "MyAuthService",
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret,
});
        return totp;

    }catch(error){
        throw new Error("Failed to generate TOTP");
    }
}


