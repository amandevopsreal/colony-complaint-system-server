const connectToMngo = require("./db");
const express = require("express")
const cors = require("cors");

connectToMngo();
const app = express()
const port = 5000;

app.use(express.json())
app.use(cors());

//Available routes
app.use("/api/auth", require('./routes/authRoutes'))

app.listen(port, () => {
    console.log(`App is running on port ${port}`)
})