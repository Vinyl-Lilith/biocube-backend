import app from "./src/index.js";
import { connectDB } from "./src/config/db.js";

const PORT = process.env.PORT || 10000;

connectDB();

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
