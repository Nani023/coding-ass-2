const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const db = new sqlite3.Database("twitterClone.db");

const SECRET_KEY = "your_secret_key";

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).send("Invalid JWT Token");
  }
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).send("Invalid JWT Token");
  }
};

// API 1: Register a new user
app.post("/register/", async (req, res) => {
  const { name, username, password, gender } = req.body;
  if (password.length < 6) {
    return res.status(400).send("Password is too short");
  }

  db.get(
    "SELECT * FROM user WHERE username = ?",
    [username],
    async (err, row) => {
      if (row) {
        return res.status(400).send("User already exists");
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        "INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)",
        [name, username, hashedPassword, gender],
        function () {
          res.send("User created successfully");
        }
      );
    }
  );
});

// API 2: Login a user
app.post("/login/", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM user WHERE username = ?",
    [username],
    async (err, row) => {
      if (!row) {
        return res.status(400).send("Invalid user");
      }
      const validPassword = await bcrypt.compare(password, row.password);
      if (!validPassword) {
        return res.status(400).send("Invalid password");
      }

      const token = jwt.sign({ userId: row.user_id }, SECRET_KEY);
      res.send({ jwtToken: token });
    }
  );
});

// API 3: Get latest tweets from followed users
app.get("/user/tweets/feed/", authenticateToken, (req, res) => {
  const { userId } = req.user;
  db.all(
    `
        SELECT tweet.tweet, tweet.date_time, user.username 
        FROM tweet 
        JOIN follower ON tweet.user_id = follower.following_user_id 
        JOIN user ON tweet.user_id = user.user_id 
        WHERE follower.follower_user_id = ?
        ORDER BY tweet.date_time DESC 
        LIMIT 4`,
    [userId],
    (err, rows) => {
      res.send(rows);
    }
  );
});

// API 4: Get list of people the user follows
app.get("/user/following/", authenticateToken, (req, res) => {
  const { userId } = req.user;
  db.all(
    `
        SELECT user.name FROM user 
        JOIN follower ON user.user_id = follower.following_user_id 
        WHERE follower.follower_user_id = ?`,
    [userId],
    (err, rows) => {
      res.send(rows.map((row) => row.name));
    }
  );
});

// API 5: Get list of followers
app.get("/user/followers/", authenticateToken, (req, res) => {
  const { userId } = req.user;
  db.all(
    `
        SELECT user.name FROM user 
        JOIN follower ON user.user_id = follower.follower_user_id 
        WHERE follower.following_user_id = ?`,
    [userId],
    (err, rows) => {
      res.send(rows.map((row) => row.name));
    }
  );
});

// API 6: Get tweet details
app.get("/tweets/:tweetId/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.get(
    `
        SELECT tweet.tweet, tweet.date_time, 
               (SELECT COUNT(*) FROM like WHERE like.tweet_id = ?) AS likes, 
               (SELECT COUNT(*) FROM reply WHERE reply.tweet_id = ?) AS replies 
        FROM tweet 
        JOIN follower ON tweet.user_id = follower.following_user_id 
        WHERE tweet.tweet_id = ? AND follower.follower_user_id = ?`,
    [tweetId, tweetId, tweetId, userId],
    (err, row) => {
      if (!row) {
        return res.status(401).send("Invalid Request");
      }
      res.send(row);
    }
  );
});

// API 7: Get likes for a tweet
app.get("/tweets/:tweetId/likes/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.all(
    `
        SELECT user.username FROM user 
        JOIN like ON user.user_id = like.user_id 
        WHERE like.tweet_id = ? 
          AND like.user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`,
    [tweetId, userId],
    (err, rows) => {
      if (!rows.length) {
        return res.status(401).send("Invalid Request");
      }
      res.send({ likes: rows.map((row) => row.username) });
    }
  );
});

// API 8: Get replies for a tweet
app.get("/tweets/:tweetId/replies/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.all(
    `
        SELECT user.name, reply.reply 
        FROM reply 
        JOIN user ON reply.user_id = user.user_id 
        WHERE reply.tweet_id = ? 
          AND reply.user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`,
    [tweetId, userId],
    (err, rows) => {
      if (!rows.length) {
        return res.status(401).send("Invalid Request");
      }
      res.send(rows);
    }
  );
});

// API 9: Get all tweets by the user
app.get("/user/tweets/", authenticateToken, (req, res) => {
  const { userId } = req.user;

  db.all(
    `
        SELECT tweet.tweet, 
               (SELECT COUNT(*) FROM like WHERE like.tweet_id = tweet.tweet_id) AS likes, 
               (SELECT COUNT(*) FROM reply WHERE reply.tweet_id = tweet.tweet_id) AS replies, 
               tweet.date_time 
        FROM tweet 
        WHERE tweet.user_id = ?`,
    [userId],
    (err, rows) => {
      res.send(rows);
    }
  );
});

// API 10: Post a tweet
app.post("/user/tweets/", authenticateToken, (req, res) => {
  const { tweet } = req.body;
  const { userId } = req.user;

  db.run(
    "INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, ?)",
    [tweet, userId, new Date()],
    function () {
      res.send("Created a Tweet");
    }
  );
});

// API 11: Delete a tweet
app.delete("/tweets/:tweetId/", authenticateToken, (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  db.run(
    "DELETE FROM tweet WHERE tweet_id = ? AND user_id = ?",
    [tweetId, userId],
    function () {
      if (this.changes === 0) {
        return res.status(401).send("Invalid Request");
      }
      res.send("Tweet Removed");
    }
  );
});

// Export app instance
module.exports = app;
