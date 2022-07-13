const mongoose = require("mongoose");
require("dotenv").config();

mongoose
  .connect(
    "mongodb+srv://IsaacNewtonTingo:Icui4cu1998@cluster0.lthcd.mongodb.net/?retryWrites=true&w=majority"
  )
  .then(() => {
    console.log("DB connected");
  })
  .catch((err) => {
    console.log(err);
  });
