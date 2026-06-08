
import { describe , it , expect } from "vitest";
import Request from "supertest"
import app from "../../../src/app";



describe("Signup Tests",()=>{
    it("should signup a user successfully", async () => {
        // Test implementation here
        const Input = {
            email:"test@example.com",
            password:"password123"
        }
        // Simulate a signup request and assert the response
        let req =  Request(app);
        req.post("/api")
       
    })

})