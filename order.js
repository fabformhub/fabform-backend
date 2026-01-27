var arguments = process.argv

const mail = require("./mail")
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./db.db');

const msg = `

Hello

Thank you for your FabForm order.

You have successfully been upgraded to the Lifetime Plan.

We hope you enjoy using FabForm.

When you login to fabform, if it still shows you are on the free plan.
Press Ctrl+F5 to refresh the page with the lifetime plan settings.

Regards,

The FabForm Team.
`
const subject = 'FabForm order'
email = arguments[2]

db.run(`UPDATE users SET tier = 1 WHERE email =?`, [email], function(err) {
       mail.sendMail("info@fabform.io",email,"info@fabform.io",subject,msg)
       console.log(`Sent to ${email}`)
  })
