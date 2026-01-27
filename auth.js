import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import { findOrCreateUser } from "./db.js";
import nanoid from "nanoid";

async function findOrCreateUserFromGoogle(googleUser) {
  const email = googleUser.email;
  const name = googleUser.name;
  const googleId = googleUser.sub;

  return new Promise((resolve, reject) => {
    // 1. Check if user exists
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
      if (err) return reject(err);

      if (row) {
        // User already exists
        return resolve(row);
      }

      // 2. Create new user
      const uid = nanoid.nanoid(25);

      db.run(
        `INSERT INTO users(email, password, verified, uid, google_id)
         VALUES(?,?,?,?,?)`,
        [email, null, 1, uid, googleId],
        function (err2) {
          if (err2) return reject(err2);

          resolve({
            id: this.lastID,
            email,
            name,
            verified: 1,
            uid,
            google_id: googleId,
            tier: "free"
          });
        }
      );
    });
  });
}

const router = express.Router();

// 1. Redirect user to Google
router.get("/google", (req, res) => {
  const redirect =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + process.env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + encodeURIComponent("https://fabform.io/f/auth/google/callback") +
    "&response_type=code" +
    "&scope=openid%20email%20profile";

  res.redirect(redirect);
});

// 2. Google sends user back here
router.get("/google/callback", async (req, res) => {
  const code = req.query.code;

  try {
    // Exchange code for Google tokens
    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: "https://fabform.io/f/auth/google/callback"
      }
    );

    const { id_token } = tokenRes.data;

    // Decode Google ID token (contains email + name)
    const googleUser = JSON.parse(
      Buffer.from(id_token.split(".")[1], "base64").toString()
    );

    // Create or find user in your DB
    const user = await findOrCreateUser(googleUser);

    // Create your JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, tier: user.tier },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Set cookie for app.fabform.io
    res.cookie("fabform_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      domain: ".fabform.io",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Redirect to Svelte success page
    res.redirect("https://app.fabform.io/loginsuccess");

  } catch (err) {
    console.error("Google OAuth error:", err);
    res.redirect("https://app.fabform.io/login");
  }
});

export default router;

