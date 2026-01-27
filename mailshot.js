const mail = require("./mail")
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./db.db');

const msg = `

Hey User,

Oops! It looks like we goofed up and missed sending out those verification codes. Sorry about that! Everything’s fixed now, and you should be good to go.

Thanks for your patience!

Cheers,  
FabForm Team

`
const subject = 'Oops! FabForm.io Registration Glitch Fixed';

function sleep(millis) {
    return new Promise(resolve => setTimeout(resolve, millis));
}

let emails =[]


async function main() {
const query = `
SELECT * FROM users WHERE tier = 0 AND created_at >= date('now', '-30 days')

`;

// Execute the query
db.all(query, (error, rows) => {
    if (error) {
        console.error("Error fetching data:", error);
        return;
    }

    // Process the result rows
    rows.forEach(row => {
  emails.push(row.email)

    });


for (var i= 0; i <=emails.length; i++){

 console.log(emails[i]);
  mail.sendMail(emails[i],"",subject,msg)
}
})
}

main();

