/* Required */
const express = require("express");
const app = express();
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { MongoClient } = require("mongodb");
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
  const { authorization } = req.headers;
  try {
    const token = authorization.split(" ")[1];
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.userInfo = decoded;
    next();
  } catch (error) {
    res.send({ message: error });
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
        return res.send({ message: "Email already exist" });
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
      res.send({ message: "Error happened try again" });
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
          res.send({ message: "Authentication Error" });
        }
      } else {
        res.send({ message: "Authentication Error" });
      }
    } catch (error) {
      res.send({ message: "Authentication Error" });
    } finally {
      await client.close();
    }
  });

  /* Protected Route */
  app.get("/verification", guard, (req, res) => {
    res.send(req.userInfo);
  });
}
run().catch(console.dir);
