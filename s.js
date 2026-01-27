const express = require('express')
const he = require('he');
const nanoid = require('nanoid')
const ejs = require('ejs');
const sqlite3 = require('sqlite3');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const morgan = require('morgan');
const favicon = require('serve-favicon');
const os = require('os');
const http2 = require('http2');
const mail = require('./mail.js');
const db = new sqlite3.Database('./db.db');
const fs = require('fs');
const path = require('path');
const multer = require('multer')
const util = require('util');
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

require('dotenv').config();

// Convert db.all and db.get to promises
//
//
const dbAllAsync = util.promisify(db.all.bind(db));
const dbGetAsync = util.promisify(db.get.bind(db));

function webHook(webhookUrl,jsonData) {
	axios.post(webhookUrl, jsonData)
		.then(response => {
			console.log('Webhook successfully sent.');
		})
		.catch(error => {
			console.error('Error sending webhook:', error.message);
		});
}

// Set up Multer storage
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, '/var/www/uploads/');
	},
	filename: (req, file, cb) => {
		cb(null, file.originalname);
	},
});

// Set up Multer with the configured storage engine
const upload = multer({
	storage: storage
});
const stripe = require('stripe')(process.env.STRIPE_API_KEY);

//
//const sheets = require('./sheets.js');
//

const app = express();

function isEmail(value) {
	var regexPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}    \.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
	return regexPattern.test(value);
}

// Define the URL of the frendlycaptcha API endpoint
const friendlyCaptchaiApiUrl = 'https://api.friendlycaptcha.com/api/v1/siteverify';


var email
var secret = 'A1S1J4O21B1U8I5SJC03L9UFUEMF57CLHCOPDVV7QU2OTJ6CLAQ27RGEBG';
var siteKey = 'FCMH6UHMB0UDUCVL'

app.use(morgan('tiny'))
//app.use(cors())
const endpointSecret = "whsec_b6kNnUBEDqEvSUvnPJEB8ddRyjaP9kty";

app.get('/f/ref/:id', function(req, res) {
	//var id = req.params.id;
	res.redirect('/');

})

// Had to put this before the app.use(express.json()) // for json
//
app.post('/f/order_event', express.raw({
	type: 'application/json'
}), (request, response) => {

	const sig = request.headers['stripe-signature'];

	let event;

	try {
		event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
	} catch (err) {
		response.status(400).send(`Webhook Error: ${err.message}`);
		return;
	}

	// Handle the event
	switch (event.type) {
		case 'charge.succeeded':
			const payInfo = event.data.object;

			// Extract customer information
			const customerEmail = payInfo.billing_details.email;
			const customerName = payInfo.billing_details.name;

			const msg = `

Hello ${customerName}

Thank you for your FabForm order.

You have successfully been upgraded to the Lifetime Plan.

We hope you enjoy using FabForm.

When you login to fabform, if it still shows you are on the free plan.
Press Ctrl+F5 to refresh the page with the lifetime plan settings.

Regards,

The FabForm Team.

`
			const subject = 'FabForm order'
			db.run(`UPDATE users SET tier = 1 WHERE email =?`, [customerEmail], function(err) {
				mail.sendMail(customerEmail, "", subject, msg)
				// Send me a copy of the order email
				mail.sendMail("irishgeoff@yahoo.com","", subject + ' (COPY)', msg);
			})

			// Then define and call a function to handle the event charge.succeeded
			break;
			// ... handle other event types
		default:
			console.log(`Unhandled event type ${event.type}`);
	}

	response.json({
		received: true
	});

});

app.use(express.json()) // for json
app.use(express.urlencoded({
	extended: true
}))

app.set("view engine", "ejs");


app.use(session({
	store: new SQLiteStore({
		db: 'sessions.sqlite',       // Name of the SQLite DB file
		dir: './data',                 // Directory where the DB file will be stored
		// You can pass additional options if needed
	}),
	secret: 'your-secret-key',     // Use a strong secret in production
	resave: false,
	saveUninitialized: false,      // Only save sessions that are modified
	cookie: {
		secure: false,               // Set true if using HTTPS
		maxAge: 1000 * 60 * 60       // Example: 1 hour
	}
}));

app.use((req, res, next) => {
	console.log(`Session ID: ${req.sessionID}`);
	next();
});

// Endpoint to retrieve the UID and JWT token from the database or create them if they don't exist
app.get('/f/get-submission-api/:id', (req, res) => {
	const id = req.params.id;

	// Retrieve UID and JWT token for the endpoint from the database
	db.get("SELECT id, uid, token FROM endpoints WHERE id = ?", [id], (err, row) => {
		if (err) {
			console.error('Error retrieving UID and token:', err);
			res.status(500).json({ status: 'error', message: 'Internal server error' });
			return;
		}

		// If UID and jwt exist, return them
		if (row && row.uid && row.token) {
			console.log(`Retrieved UID and token for endpoint ${id}: UID=${row.uid}, token=${row.token}`);
			res.json(row);
			return;
		}

		// If UID doesn't exist, generate a new one
		const uid = nanoid.nanoid(); // Generate UI

		const token = nanoid.nanoid(10);

		// Update UID and token in the database
		db.run("UPDATE endpoints SET uid = ?, token = ? WHERE id = ?", [uid, token, id], function(err) {
			if (err) {
				console.error('Error updating UID and token :', err); res.status(500).json({ status: 'error', message: 'Internal server error' });
				return;
			}
			console.log(`Created UID ${uid} and token for endpoint ${id}: UID=${uid}, TOKEN=${token}`);
			res.json(row);
		});
	});
});


app.get("/f/me", (req, res) => {
	const token = req.cookies.session;

	if (!token) {
		return res.status(401).json({ error: "Not authenticated" });
	}

	try {
		const user = jwt.verify(token, process.env.JWT_SECRET);

		// You can return whatever fields you want the frontend to use
		return res.json({
			email: user.email,
			name: user.name,
			picture: user.picture,
			id: user.id,     // optional if you store it
			tier: user.tier  // optional if you store it
		});
	} catch (err) {
		return res.status(401).json({ error: "Invalid token" });
	}
});




const client = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.GOOGLE_REDIRECT_URI,
});

// Start Google OAuth
app.get("/f/auth/google", (req, res) => {
  const url = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["openid", "profile", "email"],
  });

  res.redirect(url);
});

// Google OAuth callback
app.get("/f/auth/google/callback", async (req, res) => {
  try {
    const { tokens } = await client.getToken(req.query.code);
    const idToken = tokens.id_token;

    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    const sessionToken = jwt.sign(
      {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("session", sessionToken, {
      httpOnly: true,
      secure: true,        // fabform.io uses HTTPS
      sameSite: "lax",
      path: "/",
    });

    res.redirect("https://app.fabform.io/login-success");
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error");
  }
});




app.get('/f/get-user-info/:email', (req, res) => {
	var email = req.params.email
	db.get("SELECT id, first_name, last_name from users where email=?", [email], (error, row) => {
		if (row) {
			res.json(row)
		} 
		else {
			res.status(404).json({
				status: 'error',
				message: 'User not found',
				code: 404})
		}
	})
})

app.post('/f/update-user-info', (req, res) => {
	const { firstName, lastName, email } = req.body;
	db.run("UPDATE users SET first_name = ?, last_name = ? WHERE email = ?", [firstName, lastName, email], function(error) {
		res.json({
			status: 'success',
			message: 'User information updated successfully'
		});	
	})
})

app.post('/f/check-email', (req, res) => {
	email = req.body.email

	db.get("SELECT id, email from users where email=?", [email], (error, row) => {
		if (row) {
			res.json({
				success: true,
				user_id: row.id
			})
		} else {
			res.json({
				success: false
			})
		}
	})
})

app.get('/f/get-files/:endpoint_id', function(req, res) {
	var endpoint_id = req.params.endpoint_id;

	db.all("SELECT id, name, created_at, endpoint_id from files where endpoint_id =?", [endpoint_id], (error, rows) => {
		if (rows) {
			res.json(rows)
		} else {
			res.json({
				success: "false"
			})
		}
	})

})


app.post('/f/forgot-password', (req, res) => {
	let email = req.body.email

	db.get("SELECT id, email, password from users where email=?", [email], (error, row) => {
		if (row) {
			let msg = `

    Your password for fabform.io is  ${row.password}

`
			mail.sendMail(email, "", "password reminder for fabform.io", msg)
			res.json({
				status: "sent"
			})
		} else res.json({
			status: "sent"
		})
	})
})

function updateLastLogin(email) {
	const sql = `UPDATE users SET last_login_at = datetime('now') WHERE email = ?`;
	db.run(sql, [email], function(err) {

		if (err) {
			return console.error('Error updating last_login_at:', err.message);
		}
		console.log(`Last login updated successfully for user with email ${email}`);
	});
}

app.post('/f/isTrialActive', (req, res) => {
	email = req.body.email
	const sql =`
SELECT id, email, tier, created_at,
       CASE
	   WHEN DATE(created_at, '+7 days') <= DATE('now', 'localtime') THEN 0
	   ELSE 1
       END AS isTrialActive
FROM users
where email = '${email}';
`
	db.get(sql, [email], (error, row) => {
		if (row) {
			res.json({
				status: "ok",
				user_id: row.id,
				email: row.email,
				tier: row.tier,
				isTrialActive: row.isTrialActive
			})
		} else res.json({
			status: "false"
		})
	})
})


app.post('/f/login', (req, res) => {
	email = req.body.email
	password = req.body.password

	db.get("SELECT id, email, password, verified, tier from users where email=? and password=?", [email, password], (error, row) => {
		if (row) {
			if (row.verified == 1) {
				updateLastLogin(email)
				res.json({
					status: "loggedIn",
					user_id: row.id,
					email: row.email,
					tier: row.tier
				})
			} else res.json({
				status: "notVerified"
			})
		} else res.json({
			status: "false"
		})
	})
})

app.post('/f/signup', (req, res) => {
    let email = req.body.email
    let password = req.body.password
    let uid = nanoid.nanoid(25)
    db.run(`INSERT INTO users(email,password,verified,uid) VALUES(?,?,?,?)`, [email, password, 0, uid], function(err) {
        sendEmailVerification(email, uid)
        res.json({
            success: true,
            user_id: this.lastID
        })
    })
})


app.post('/f/change-password', (req, res) => {
const { newPassword, email } = req.body;
 db.run("UPDATE users SET password = ? WHERE email = ?", [newPassword, email], function(error) {
 res.json({
            status: 'success',
            message: 'Password successfully changed'
        });	
 })
})

function sendEmailVerification(email, uid) {
    const msg = `
    <div style="font-family: Arial, sans-serif; background:#f5f5f5; padding:40px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:auto; background:white; border-radius:8px; overflow:hidden;">
        <tr>
          <td style="background:#4a6cf7; padding:20px; text-align:center; color:white; font-size:24px; font-weight:bold;">
            Verify Your Email
          </td>
        </tr>

        <tr>
          <td style="padding:30px; font-size:16px; color:#333;">
            <p>Hello,</p>

            <p>Please confirm that you'd like to add the following email address to your FabForm account:</p>

            <p style="font-size:18px; font-weight:bold; color:#4a6cf7;">
              ${email}
            </p>

            <p>To complete verification, click the button below:</p>

            <div style="text-align:center; margin:30px 0;">
              <a href="${process.env.API_LOCATION}verify_email/${uid}"
                 style="
                    background:#d93025;
                    color:white;
                    padding:14px 28px;
                    text-decoration:none;
                    border-radius:6px;
                    font-size:16px;
                    font-weight:bold;
                    display:inline-block;
                 ">
                Verify Email
              </a>
            </div>

            <p>If you didn’t request this change, you can safely ignore this email.</p>

            <p style="margin-top:40px; color:#777; font-size:14px;">
              — The FabForm Team
            </p>
          </td>
        </tr>
      </table>
    </div>
    `;

    mail.sendMail(
        email,
        "",
        "Action Required: Verify email linked to FabForm",
        msg
    );
}

function sendEmailWelcome(email) {
    const msg = `
    <div style="font-family: Arial, sans-serif; background:#f5f5f5; padding:40px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:auto; background:white; border-radius:8px; overflow:hidden;">
        
        <tr>
          <td style="background:#4a6cf7; padding:20px; text-align:center; color:white; font-size:24px; font-weight:bold;">
            Welcome to FabForm
          </td>
        </tr>

        <tr>
          <td style="padding:30px; font-size:16px; color:#333;">
            <p>Hello,</p>

            <p>Welcome to <strong>FabForm</strong> — we’re excited to have you on board!</p>

            <p>You've just joined a simple, powerful backend service for handling form submissions without the hassle.</p>

            <p>If you ever have questions or need help, feel free to reach out. We're here for you.</p>

            <div style="text-align:center; margin:30px 0;">
              <a href="https://fabform.io"
                 style="
                    background:#d93025;
                    color:white;
                    padding:14px 28px;
                    text-decoration:none;
                    border-radius:6px;
                    font-size:16px;
                    font-weight:bold;
                    display:inline-block;
                 ">
                Get Started
              </a>
            </div>

            <p>Thanks for joining us.</p>

            <p style="margin-top:40px; color:#777; font-size:14px;">
              — The FabForm Team
            </p>
          </td>
        </tr>

      </table>
    </div>
    `;

    mail.sendMail(
        email,
        "",
        "Welcome to fabform.io",
        msg
    );
}

app.post('/f/resend-email-verification', (req, res) => {
    email = req.body.email
    db.get("SELECT id, email, uid from users where email=?", [email], (error, row) => {
        if (row) {
            sendEmailVerification(email, row.uid)
            res.json({
                success: "true"
            })
        } else {
            res.json({
                success: "false"
            })
        }
    })
})

// verify email address
//
app.get('/f/verify_email/:uid', function(req, res) {
    title = "verify email"
    var uid = req.params.uid;
    var email

    db.get("SELECT uid, email, verified from users where uid=?", [uid], (error, row) => {
        if (row) {
            email = row.email
            db.run(`UPDATE users SET verified = 1 WHERE uid =?`, [uid], function(err) {
                sendEmailWelcome(email);
                res.redirect('https://fabform.io/success');
            })
        } else {
            res.redirect('/');
        }
    })
})

// GET /test 
app.get("/f/test", (req, res) => 
	{ 
       mail.sendMail("irishgeoff@yahoo.com", "info@fabform.io", "test route and email ", "<p>Hello there! from test</p>");
		res.json({ message: "GET test OK" }); 
	});



app.get('/f/:id', function(req, res) {
    var title = "fabform.io"
    var id = req.params.id;
    var formCode = he.encode(`You need to set the FORM action to:- <form action="https://fabform.io/f/${id}" method="post"> to work.`)
	
   var helperInfo = `<br><strong><a target ="blank" href="https://docs.fabform.io">For help, please refer to the FabForm.io documentation.</a></strong>`

    res.render("error", {
        title: title,
        message: formCode + helperInfo
    })
})

//   Endpoint to count form submissions for a user by ID in the current month
app.get('/f/submissions-count/:userId', (req, res) => {
  const userId = req.params.userId;
  // Get the current month and year
  const currentDate = new Date();
  const currentYear = currentDate.getFullYear();
  const currentMonth = currentDate.getMonth() + 1; // Month is zero-based
  
  // Start and end date of the current month
  const startDate = `${currentYear}-${currentMonth.toString().padStart(2, '0')}-01`;
  const endDate = `${currentYear}-${(currentMonth + 1).toString().padStart(2, '0')}-01`;

  const sql = `
    SELECT COUNT(*) AS total_submissions
    FROM submissions AS s
    JOIN endpoints AS e ON s.endpoint_id = e.id
    JOIN users AS u ON e.user_id = u.id
    WHERE u.id = ? AND s.created_at >= ? AND s.created_at < ?;
  `;

  db.get(sql, [userId, startDate, endDate], (err, row) => {
    if (err) {
      console.error('Error querying the database:', err.message);
      res.status(500).send('Internal Server Error');
    } else {
      const totalSubmissions = row.total_submissions || 0;
      res.json({ userId, totalSubmissions });
    }
  });
});

// POST A FORM 
// Submit
//

// Helper functions to wrap db.run and db.get into promises:
function runDb(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function getDb(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function fillTemplate(formData, template) {
    // Check if the template is empty
    if (!template || template.trim() === '') {
        return JSON.stringify(formData);
    } else {
        // Replace placeholders with values
        for (const key in formData) {
            if (formData.hasOwnProperty(key)) {
                const placeholder = '{' + key + '}';
                while (template.includes(placeholder)) {
                    template = template.replace(placeholder, formData[key]);
                }
            }
        }
        return template;
    }
}

app.post('/f/success', async (req, res) => {
    const token = req.body['frc-captcha-solution'];
    const friendlyCaptchaData = {
      solution: token,
      secret: secret,
      sitekey: siteKey,
    };
      console.log("session variables")
      console.log(req.session.data)

     const response = await axios.post(friendlyCaptchaiApiUrl, friendlyCaptchaData);
      if (response.data.success) {
      return res.json({ status: 'success', message: 'ok', data: req.session.data  });
      }
      return res.json({ status: 'fail', message: 'fail' });

});



app.post('/f/test/:id', async (req, res) => {
req.session.data = req.body;  

return res.render("captcha2", {
        "title":"my title",
          message: "hello message",
          siteKey,
        });
})

//Submit
//
//
// Our route handler now uses async/await:
app.post('/f/:id', upload.any(), async (req, res) => {
  try {
    const title = "fabform.io";
    const id = req.params.id;
    const files = req.files;
    const isJsonRequest = req.get('Content-Type') === 'application/json';
    const hasFiles = files && files.length > 0;

    // (upload.any() already processes files; additional handling can go here if needed)
    if (req.body && req.body.email) {
      req.session.email = req.body.email;
    }

    const token = req.body['frc-captcha-solution'];
    const friendlyCaptchaData = {
      solution: token,
      secret: secret,
      sitekey: siteKey,
    };
    console.log(req.body)

    // Save form data (if any) in the session when not doing captcha
    if (!token && Object.keys(req.body).length > 0) {
      req.session.formData = JSON.stringify(req.body);
    }

    // Save file info to the database, if any files were uploaded:
    if (files) {
      const fileData = files.map(file => ({
        name: file.originalname,
        endpoint_id: id,
      }));

      await runDb('BEGIN TRANSACTION');
      for (const data of fileData) {
        await runDb('INSERT INTO files (name, endpoint_id) VALUES (?, ?)', [
          data.name,
          data.endpoint_id,
        ]);
      }
      await runDb('COMMIT');
    }

    // Check for empty form data (e.g. "{}" has a length of 2)
    if (req.session.formData && req.session.formData.length == 2) {
      const message = `Can't send an empty form. <br/>
Make sure you have placed the "name" attribute in all your form elements.<br> 
Also, to prevent empty form submissions, see the "required" property.`;
      return res.render("error", { title, message });
    }

    // Retrieve the endpoint from the database
    const row = await getDb("SELECT * FROM endpoints WHERE id=?", [id]);
    if (!row) {
      const message = `
The form isn't set up yet. If this is your website, please log in to 
<strong><a target="_blank" href="https://fabform.io">fabform</a></strong> and set up the form. 
Then, update your HTML or JavaScript with the new form endpoint. 
<strong><a target="_blank" href="https://docs.fabform.io">For help, please refer to the FabForm.io documentation.</a></strong>`;
      return res.render("error", { title, message });
    }

    // If no captcha token was provided...
    if (!token) {
   //   if (!isJsonRequest) {
        return res.render("captcha", {
          title,
          message: row.message,
          siteKey,
        });
     // }
    } else {
        console.log("here")
	console.log(req.session.formData)

      // Verify captcha token:
      const response = await axios.post(friendlyCaptchaiApiUrl, friendlyCaptchaData);
      if (response.data.success) {

    const formData = JSON.parse(req.session.formData);
    const defSubject = `fabform.io form ${row.id} submission`;
    const respFormData = fillTemplate(formData, row.email_template);
    const autoRespFormData = fillTemplate(formData, row.auto_resp_template);

    // Process only if _gotcha is empty or not set
    if (!formData._gotcha || formData._gotcha === '') {
      if (formData._gotcha !== undefined) {
        delete formData._gotcha;
      }
      await runDb(`INSERT INTO submissions(endpoint_id, form_data) VALUES(?, ?)`, [
        id,
        JSON.stringify(formData),
      ]);

      // Get the user's tier from the database:
      const userRow = await getDb(
        `SELECT u.tier FROM users u
         JOIN endpoints e ON u.id = e.user_id
         WHERE e.id = ?`,
        [id]
      );
      const tier = userRow.tier;

      // Send notification email if conditions are met:
      if (isEmail(row.resp_email) && row.email_notification && tier == 1) {
        console.log(`sending response email to ${row.resp_email}`);
        mail.sendMail(
          row.resp_email,
          req.session.email,
          row.resp_email_subject || defSubject,
          respFormData
        );
      }
      // Send auto-response email if conditions are met:
      if (isEmail(req.session.email) && row.auto_resp && tier == 1 ) {
        console.log(`sending auto response email to ${req.session.email}`);
        mail.sendMail(
          req.session.email,
          row.reply_to,
          row.auto_resp_email_subject || defSubject,
          autoRespFormData
        );
      }
    }

    // Return JSON if that's the request type
    if (isJsonRequest) {
      return res.json({ success: "true" });
    }

    // Trigger a webhook if one is defined
    if (row.webhook_url) {
      const jsonData = {
        event: "form.submitted",
        formName: row.name,
        data: formData,
      };
      webHook(row.webhook_url, jsonData);
    }

    // Redirect if a redirect URL is defined
    if (row.redirect_url) {
      return res.redirect("https://" + row.redirect_url);
    }

    // Otherwise, render a success page
    return res.render("success", {
      id,
      title,
      message: row.message,
      siteKey,
    });
      } else {
        return res.render("error", { title, message: "verification failed." });
      }
    }
  } catch (err) {
    console.error("Error in /f/:id route:", err);
    return res.render("error", { title: "fabform.io", message: "An error occurred." });
  }
});

    
app.get('/f/endpoints/:user_id', async (req, res) => {
  const user_id = req.params.user_id;

  try {
    const rows = await dbAllAsync("SELECT id, name, message FROM endpoints WHERE user_id=?", [user_id]);
    res.json(rows || { success: "false" });
  } catch (error) {
    res.status(500).json({ success: "false", error: error.message });
  }
});

app.get('/f/endpoint/:id', async (req, res) => {
  const id = req.params.id;

  try {
    const row = await dbGetAsync("SELECT * FROM endpoints WHERE id=?", [id]);
    res.json(row || { success: "false" });
  } catch (error) {
    res.status(500).json({ success: "false", error: error.message });
  }
});

app.post('/f/endpoint/:id', function(req, res) {
  const {
    id,
    name,
    respEmail,
    respEmailSubject,
    autoRespEmailSubject,
    message,
    replyTo,
    emailNotification,
    autoResp,
    reCaptcha,
    emailTemplate,
    autoRespTemplate,
    googleSheetId,
    webhookUrl,
    redirectUrl
  } = req.body;

  db.run(
    `UPDATE endpoints 
     SET name = ?, 
         message = ?, 
         resp_email = ?, 
         resp_email_subject = ?, 
         email_notification = ?, 
         auto_resp_email_subject = ?, 
         auto_resp = ?, 
         email_template = ?, 
         auto_resp_template = ?, 
         google_sheet_Id = ?, 
         webhook_url = ?, 
         redirect_url = ?, 
         reply_to = ?
     WHERE id = ?`,
    [
      name,
      message,
      respEmail,
      respEmailSubject,
      emailNotification,
      autoRespEmailSubject,
      autoResp,
      emailTemplate,          // ← FIXED
      autoRespTemplate,
      googleSheetId,
      webhookUrl,
      redirectUrl,
      replyTo,
      id
    ],
    function(err) {
      if (err) {
        console.error("DB update error:", err);
        return res.json({ success: false });
      }

      res.json({ success: true });
    }
  );
});


app.post('/f/delete-endpoint/:id', function(req, res) {
var id = req.params.id;
db.run(`DELETE FROM endpoints WHERE id =?`, [id], function(err) {
res.json({
success: true
                        })
                    })
                })

                app.post('/f/delete-submissions/:values', function(req, res) {
                    const valuesArray = req.params.values.split(',');

                    const sqlQuery = `DELETE FROM submissions WHERE id IN (${valuesArray})`;
                    db.run(sqlQuery, function(err) {
                        res.json({
                            success: true
                        })
                    })

                })

                app.post('/f/delete-account/:user_id', function(req, res) {
                    let user_id = req.params.user_id;
                    db.all("SELECT id, user_id from endpoints where user_id=?", [user_id], (error, rows) => {
                        if (rows) {
                            rows.forEach(r => {
                                db.run(`DELETE FROM submissions WHERE endpoint_id =?`, [r.id], function(err) {})

                            })

                            db.run(`DELETE FROM endpoints WHERE user_id =?`, [user_id], function(err) {})

                            db.run(`DELETE FROM users WHERE id =?`, [user_id], function(err) {
                                res.json({
                                    success: true
                                })
                            })
                        }
                    })
                })

                app.get('/f/submissions/:endpoint_id', function(req, res) {

                    var endpoint_id = req.params.endpoint_id;
                    db.all("SELECT endpoint_id,id, created_at, form_data from submissions where endpoint_id=? ORDER BY id DESC", [endpoint_id], (error, rows) => {
                        if (rows) {
                            let newRows = [];
                            for (r of rows) {
                                newRows.push({
                                    id: r.id,
                                    created_at: r.created_at,
                                    form_data: JSON.parse(r.form_data)
                                })
                            }
                            res.json(newRows)
                        } else {
                            res.json({
                                success: "false"
                            })
                        }
                    })

                })

app.post('/f/veilmail/', function(req, res) {
    const emails = req.body;

    db.serialize(() => {
        const stmt = db.prepare('INSERT INTO veilmail (email) VALUES (?)');

        emails.forEach((email) => {
            stmt.run(email, (err) => {
                if (err) {
                    console.error('Error inserting email:', err.message);
                    res.status(500).send('Error inserting email');
                }
            });
        });

        stmt.finalize();

        console.log('Bulk insert completed successfully.');
        res.status(200).send('Bulk insert completed successfully.');

        db.close();
    });
});

                app.post('/f/endpoints/:user_id', function(req, res) {
                    var user_id = req.params.user_id;
                    var id = req.body.id
                    var name = req.body.name
                    var respEmail = req.body.respEmail
                    var message = req.body.message

                    db.run(`INSERT INTO endpoints(id,name,resp_email,message,user_id) VALUES(?,?,?,?,?)`, [id, name, respEmail, message, user_id], function(err) {
                        res.json({
                            success: true
                        })
                    })

                })

                const port = '8081'
                console.log("fabform.io running..... " + port)
		app.listen(port)
