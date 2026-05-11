import sqlite3 from "sqlite3";
import { open } from "sqlite";
import * as mail from "./mail.js";

const subject = "Your FabForm Account Requires Action — Free Tier Ending Soon";

const msg = `
Hey there,

We’re reaching out with an important update about your FabForm account, and we want to make sure you have complete clarity before anything changes.

FabForm’s free tier is being discontinued soon. When this happens, your existing forms will automatically become inactive unless you upgrade. We know this is a significant shift, which is why we’re giving you advance notice — so you stay fully in control and avoid any unexpected interruptions.

Here’s the good news: you have options.

Upgrading keeps all your forms live, prevents any downtime, and unlocks higher limits, advanced features, and priority support. For many users, even the entry plan saves hours of manual work every month.

### A One‑Time Lifetime Deal (No Recurring Fees)
To make this transition easier, we’re offering a **limited lifetime plan for just £29.95**.  
You pay once — **no monthly fees, no renewals, no recurring charges ever**.

This offer is only available during the free‑tier shutdown period and won’t return once it closes.

You can review all plans here:  
https://fabform.io/pricing/

If you’re unsure which option fits your workflow or you’re facing any difficulty with this change, just reply to this email. We’ll help you choose the most cost‑effective path and make the transition smooth.

Thank you for being part of FabForm — your support genuinely means a lot to us.
`;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const db = await open({
    filename: "./db.db",
    driver: sqlite3.Database
  });

  const rows = await db.all(
    "SELECT id, email FROM users WHERE tier = 0 AND email_sent = 0;"
  );

  console.log(`Preparing to send ${rows.length} emails...`);

  for (const row of rows) {
    const { id, email } = row;

    console.log("Sending to:", email);

    let result;

    try {
      result = await mail.sendMail(email, "", subject, msg);
    } catch (err) {
      console.error("THROWN ERROR:", err);

      // STOP on thrown quota error
      if (err?.statusCode === 429 || err?.name === "daily_quota_exceeded") {
        console.error("Daily quota reached. Stopping mailshot.");
        break;
      }

      console.error("Fatal send error. Stopping mailshot.");
      break;
    }

    // 🔥 CRITICAL: detect errors returned INSIDE the result object
    if (
      !result ||
      result?.statusCode === 429 ||
      result?.name === "daily_quota_exceeded"
    ) {
      console.error("PROVIDER ERROR:", result);

      console.error("Daily quota reached. Stopping mailshot.");
      break;
    }

    // SUCCESS ONLY
    console.log("Email sent:", result);
    await db.run("UPDATE users SET email_sent = 1 WHERE id = ?", id);
    console.log("Marked as sent:", email);

    await sleep(500);
  }

  console.log("Mailshot finished.");
  await db.close();
}

main();

