// src/queues/email.queue.ts
import { Queue } from "bullmq";
import redis from "../config/redis.js"
export type EmailJobData =
  | {
      type: "email_verification";
      to: string;
      name: string;
      otp: string;
    }
  | {
      type: "password_reset";
      to: string;
      name: string;
      otp: string;  
    }
   |{
      type:"magic_link";
      to:string;
      name:string;
      otp:string;
   }

const emailQueue = new Queue<EmailJobData>("email", {
  connection: redis as any,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: "exponential",
      delay: 2000,
    },
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
  },
});

export default emailQueue;