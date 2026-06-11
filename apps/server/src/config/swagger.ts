// src/config/swagger.ts
import swaggerJsdoc from "swagger-jsdoc";

export const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "SSAVR API",
      version: "1.0.0",
      description: "API documentation for SSAVR backend",
    },
    servers: [
    
      {
        url: `${process.env.API_BASE_URL|| "http://localhost:4444"}`, // local
      },
    ],
  },
  apis: ["./src/modules/**/*route.ts"], // where your docs are written
});