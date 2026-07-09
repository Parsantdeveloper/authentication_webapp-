
import * as OTPAuth from "otpauth";
import Cryptr from "cryptr";

const cryptr = new Cryptr(process.env.TOTP_SECRET_KEY!);


 export function encryptSecret(secret: string): string {
  return cryptr.encrypt(secret);
}

 export function decryptSecret(encryptedSecret: string): string {
  return cryptr.decrypt(encryptedSecret);

}

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



