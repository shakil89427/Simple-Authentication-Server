/* Required */
const express = require("express");
const app = express();
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { MongoClient } = require("mongodb");
const nodemailer = require("nodemailer");
const port = process.env.PORT || 5000;
app.use(cors());
app.use(express.json());

/* MongoDB Login */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.4yyh4.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

/* Basic Check Route */
app.get("/", (req, res) => {
  res.send("server running");
});

app.listen(port, () => {
  console.log("listening to", port);
});

/* Auth Guard */
const guard = (req, res, next) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.userinfo = decoded;
    next();
  } catch (error) {
    next(error);
  }
};

/* Main Routes */
async function run() {
  const database = client.db("authentication");
  const users = database.collection("users");

  /* Signup */
  app.post("/signup", async (req, res) => {
    try {
      await client.connect();
      let user = req.body;
      const exist = await await users.findOne({ email: user.email });
      if (exist) {
        return res.status(403);
      }
      const encryptedPassword = await bcrypt.hash(user.password, 10);
      user.password = encryptedPassword;
      const result = await users.insertOne(user);
      if (result.acknowledged) {
        const { password, ...rest } = await users.findOne({
          email: user.email,
        });
        const token = jwt.sign(rest, process.env.SECRET_KEY, {
          expiresIn: "1hr",
        });
        res.send(token);
      }
    } catch (error) {
      res.send(error);
    } finally {
      await client.close();
    }
  });

  /* Reset Password */
  app.post("/resetpassword", async (req, res) => {
    try {
      await client.connect();
      let user = req.body.email;
      const exist = await users.findOne({ email: user });
      if (exist) {
        const { password, ...rest } = exist;
        const token = jwt.sign(rest, process.env.SECRET_KEY, {
          expiresIn: "1hr",
        });
        /* Email Top */
        let transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false,
          requireTLS: true,
          auth: {
            user: process.env.GMAIL,
            pass: process.env.GPASS,
          },
        });
        let response = await transporter.sendMail({
          from: process.env.GMAIL,
          to: user,
          subject: "Reset Password ✔",
          text: `Click the link  to reset your Password.Link is valid for 1 hr. https://shakil-authentication.netlify.app/resetpassword/${token}`,
        });
        if (response) {
          res.status(200);
        }
        /* Email Bottom */
      } else {
        res.status(404);
      }
    } catch (error) {
      res.send(error);
    } finally {
      await client.close();
    }
  });

  /* Login */
  app.post("/login", async (req, res) => {
    try {
      await client.connect();
      const user = await users.findOne({ email: req.body.email });
      if (user) {
        const validPassword = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (validPassword) {
          const { password, ...rest } = user;
          const token = jwt.sign(rest, process.env.SECRET_KEY, {
            expiresIn: "1hr",
          });
          res.send(token);
        } else {
          res.status(401);
        }
      } else {
        res.status(401);
      }
    } catch (error) {
      res.send(error);
    } finally {
      await client.close();
    }
  });

  /* Protected Route */
  app.post("/checkresettoken", guard, async (req, res) => {
    try {
      await client.connect();
      const result = await users.findOne({ email: req.userinfo.email });
      if (result.email) {
        res.status(200);
      }
    } catch (error) {
      res.send(error);
    } finally {
      await client.close();
    }
  });
  /* Confirm Password Reset*/
  app.post("/confirmreset", guard, async (req, res) => {
    try {
      await client.connect();
      const result = await users.findOne({ email: req.userinfo.email });
      if (result.email) {
        const encryptedpassword = await bcrypt.hash(
          req.body.userData.password,
          10
        );
        const updated = { $set: { password: encryptedpassword } };
        const findby = { email: result.email };
        const update = await users.updateOne(findby, updated);
        if (update.modifiedCount) {
          res.status(200);
        }
      }
    } catch (error) {
      res.send(error);
    } finally {
      await client.close();
    }
  });
}
run().catch(console.dir);
