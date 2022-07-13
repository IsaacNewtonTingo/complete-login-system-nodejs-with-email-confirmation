const express = require("express");
const router = express.Router();
require("dotenv").config();
const bcrypt = require("bcrypt");
var nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const path = require("path");

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

const sendVerificationEmail = ({ _id, email }, res) => {
  const currentUrl = "http://localhost:3000/";
  const uniqueString = uuidv4() + _id;
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Verify your email to complete your signup process.</p><p>Link <b>expires in 6hrs.</b></p><p>Press <a href=${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
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

router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        if (expiresAt < Date.now()) {
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired. Signup again";
                  res.redirect(`/user/verified/?error=true&message=${message}`);
                })
                .catch((err) => {
                  console.log(err);
                  let message = "Clearing user data failed";
                  res.redirect(`/user/verified/?error=true&message=${message}`);
                });
            })
            .catch((err) => {
              console.log(err);
              let message =
                "An error occured while clearing expired verification data";
              res.redirect(`/user/verified/?error=true&message=${message}`);
            });
        } else {
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "../views/verified.html")
                        );
                      })
                      .catch((err) => {
                        console.log(err);
                        let message =
                          "An error occured while deleting verified user";
                        res.redirect(
                          `/user/verified/?error=true&message=${message}`
                        );
                      });
                  })
                  .catch((err) => {
                    console.log(err);
                    let message =
                      "An error occured while updating user records";
                    res.redirect(
                      `/user/verified/?error=true&message=${message}`
                    );
                  });
              } else {
                let message = "Invalid verification details. Check your inbox";
                res.redirect(`/user/verified/?error=true&message=${message}`);
              }
            })
            .catch((err) => {
              let message = "An error occured while comparing unique strings";
              res.redirect(`/user/verified/?error=true&message=${message}`);
            });
        }
      } else {
        let message =
          "Account record doesn't exists or has been verified already. Please signup or login";
        res.redirect(`/user/verified/?error=true&message=${message}`);
      }
    })
    .catch((err) => {
      console.log(err);
      let message = "An error occured whilechecking verified email";
      res.redirect(`/user/verified/?error=true&message=${message}`);
    });
});

router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/verified.html"));
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
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email hasn't been verified",
            });
          } else {
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
          }
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
