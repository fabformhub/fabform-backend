require('dotenv').config();
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendMail(to, replyTo, subject, msg) {

  // Footer strings
  const footerHtml = `
    <br><br>
    <span style="color:#555;">
      Powered by 
      <a href="https://fabform.io" target="_blank" rel="noopener noreferrer" style="color:#000; font-weight:600;">
        Fabform.io
      </a>
    </span>
  `;

  try {
    const { data, error } = await resend.emails.send({
      from: "info@fabform.io",
      to: to,
      subject: subject,
      html: msg + footerHtml,
      reply_to: replyTo || "info@fabform.io"
    });

    if (error) {
      console.error("Error sending email:", error);
      return;
    }

    console.log("Email sent:", data);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

module.exports = { sendMail };

