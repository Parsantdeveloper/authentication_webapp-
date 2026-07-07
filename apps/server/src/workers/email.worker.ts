
import { Worker, type Job } from "bullmq";
import resend from "../config/email.js"
import type { EmailJobData } from "../libs/email.subscriber.js";
import { logger } from "../config/logger.js";
import redis from "../config/redis.js"

const EMAIL_TEMPLATES: Record<
  EmailJobData["type"],
  (data: EmailJobData) => {
    subject: string;
    html: string;
  }
> = {
  email_verification: (data) => ({
    subject: "Verify your email",
    html: `
      <p>Hi ${data.name},</p>
      <p>Your email verification code is:</p>
      <h2 style="letter-spacing:4px">${data.otp}</h2>
      <p>This code expires in 1 minutes.</p>
    `,
  }),

  password_reset: (data) => ({
    subject: "Reset your password",
    html: `
      <p>Hi ${data.name},</p>
      <p>Your password reset code is:</p>
      <h2 style="letter-spacing:4px">${data.otp}</h2>
      <p>This code expires in 1 minutes.</p>
    `,
  }),

  magic_link:(data)=>({
    subject:"Magic Link",
    html:`
      <p>Hi ${data.name},</p>
      <p>Click the link below to login:</p>
      <a href="${process.env.MAGIC_LINK_URL}?token=${data.otp}">Login</a>
      <p>This link expires in 10 minutes.</p>
    `
  }),
};

async function processEmailJob(job:Job<EmailJobData>){
     const {type,to} = job.data;
     const template =EMAIL_TEMPLATES[type](job.data);

     await resend.emails.send({
        from :"onboarding@resend.dev",
        to,
        subject:template.subject,
        html:template.html
     })
}


const emailWorker =new Worker<EmailJobData>("email",processEmailJob,{
    connection:redis,
    concurrency:5,
})


emailWorker.on("completed",(job)=>{
  logger.info(`[EmailWorker] Job ${job.id} (${job.data.type}) completed`);
})

emailWorker.on("failed", (job, err) => {
  logger.error(`[EmailWorker] Job ${job?.id} failed: ${err.message}`);
});


export default emailWorker;

