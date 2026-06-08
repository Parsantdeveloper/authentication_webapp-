import { describe, it, expect } from "vitest";
import { hashPassword, comparePassword } from "#/middlewares/password_hash.ts";

describe("Password Utils", () => {
  
  it("should hash password", async () => {
    const password = "password123";

    const hash = await hashPassword(password);

    expect(hash).toBeDefined();
    expect(hash).not.toBe(password);
  });

   it("should compare password correctly",async()=>{
    const password="password123";
    const hash=await hashPassword(password);
    
    const isMatch=await comparePassword(password,hash);
    expect(isMatch).toBe(true);
   })

   it("should return false for the incorrect password",async()=>{
    const password = "password123";
    const wrongPassword = "wrongpassword";
    const hash = await hashPassword(password);
    const isMatch = await comparePassword(wrongPassword, hash);
    expect(isMatch).toBe(false);
   })

});