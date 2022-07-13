const express = require("express");
const router = express.Router();
require("dotenv").config();
const bcrypt = require("bcrypt");
var nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");

const User = require("../models/user");
const UserVerification = require("../models/user-verification");

let transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for message");
    console.log(success);
  }
});

const sendVerificationEmail = ({ _id, email }, res) => {
  const currentUrl = "http://localhost:3000/";
  const uniqueString = uuid4() + _id;
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Verify your email to complete your signup process.</p><p>Link <b>expires in 6hrs.</b></p><p>Press <a href=${
      currentUrl + "users/verify/" + _id + "/" + uniqueString
    }> here </a>to proceed </p>`,
  };

  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });
      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              res.json({
                status: "Pending",
                message: "Verification email sent",
              });
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                message: "Error occured sending verification email",
              });
            });
        })
        .catch((err) => {
          res.json({
            status: "Failed",
            message: "Couldn't save verification email data",
          });
        });
    })
    .catch((err) => {
      res.json({
        status: "Failed",
        message: "Error occured hashing email data",
      });
    });
};

router.post("/signup", (req, res) => {
  let { name, email, password, dateOfBirth } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

  if (name == "" || email == "" || password == "" || dateOfBirth == "") {
    res.json({
      status: "Failed",
      message: "All fields are required",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "Failed",
      message: "Invalid name format",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "Failed",
      message: "Invalid email",
    });
  } else if (!new Date(dateOfBirth).getTime()) {
    res.json({
      status: "Failed",
      message: "Invalid date of birth format",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      message: "Password is too short",
    });
  } else {
    User.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "Failed",
            message: "User with the given email already exists",
          });
        } else {
          const salt = 10;
          bcrypt
            .hash(password, salt)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
                dateOfBirth,
                verified: false,
              });
              newUser
                .save()
                .then((result) => {
                  //Send email
                  sendVerificationEmail(result, res);
                })
                .catch((err) => {
                  res.json({
                    status: "Failed",
                    message: "Error occured while creating account",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                message: "Error occured while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        res.json({
          status: "Failed",
          message: "Erro occured when checking email",
        });
      });
  }
});

router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "Failed",
      message: "All fields are required",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                res.json({
                  status: "Success",
                  message: "Signin successfull",
                  data: data,
                });
              } else {
                res.json({
                  status: "Failed",
                  message: "Invalid password",
                });
              }
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                message: "Error occured while comparing passwords",
              });
            });
        } else {
          res.json({
            status: "Failed",
            message: "Invalid credentials entered",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "Failed",
          message: "Error occured checking existing user",
        });
      });
  }
});

module.exports = router;
