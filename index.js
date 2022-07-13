const express = require("express");
const app = express();
require("dotenv").config();

const port = process.env.PORT || 3000;

const bodyParser = require("body-parser").json;
app.use(bodyParser());

require("./config/db");

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

const UserRouter = require("./api/user");

app.use("/users", UserRouter);
