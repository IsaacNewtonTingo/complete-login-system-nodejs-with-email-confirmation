const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const port = process.env.PORT || 3000;

const bodyParser = require("body-parser").json;
app.use(bodyParser());

require("./config/db");

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

app.use(cors());
const UserRouter = require("./api/user");

app.use("/user", UserRouter);
