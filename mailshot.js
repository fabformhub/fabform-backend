const mail = require("./mail");
const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("./db.db");

const subject = "Important: FabForm Free Tier Is Being Discontinued";

const msg = `
Hey there,

We’re reaching out with an important update about your FabForm account, and we wanted to be upfront with you as early as possible.

We’re discontinuing our free tier soon. This means your existing forms will become inactive unless you upgrade to a paid plan. We know this may be unexpected, and we genuinely appreciate everyone who has supported FabForm from the early days — including you.

Our goal is to give you enough time to make the right decision for your workflow, without any surprises or sudden interruptions. Upgrading keeps all your forms active and unlocks higher limits, advanced features, and priority support.

You can review the available plans here:
https://fabform.io/pricing/

If this change creates any difficulty or you’re unsure which plan fits best, just reply to this email — we’re here to help, and we’ll do everything we can to make the transition smooth.

Thank you for being part of FabForm. We truly appreciate you.

— The FabForm Team
`;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const query = `SELECT email FROM users WHERE tier = 0;`;

  db.all(query, async (error, rows) => {
    if (error) {
      console.error("Error fetching data:", error);
      return;
    }

    const emails = rows.map(r => r.email);

    console.log(`Preparing to send ${emails.length} emails...`);

    for (const email of emails) {
      console.log("Sending to:", email);

      try {
        await mail.sendMail(email, "", subject, msg);
      } catch (err) {
        console.error("Failed to send to:", email, err);
      }

      // Throttle to avoid SMTP rate limits
      await sleep(500);
    }

    console.log("All emails sent.");
  });
}

main();

