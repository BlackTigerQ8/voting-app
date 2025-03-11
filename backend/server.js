const connectDB = require("./config/db.js");
const app = require("./app");

connectDB();

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Server started on port ${port}`));
