import { app } from "./app.js";
import { env } from "@repo/config";


app.listen(env.PORT, () => {
console.log(`Server running on port ${env.PORT}`);
});