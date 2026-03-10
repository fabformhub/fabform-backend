const { Bot } = require("grammy");
const dotenv = require("dotenv");

dotenv.config(); // Load environment variables from .env

// Get token from .env
const botToken = process.env.TELEGRAM_BOT_TOKEN;

if (!botToken) throw new Error("BOT_TOKEN is not defined in .env");

const bot = new Bot(botToken);

async function sendMessage(chatId, message) {
  try {
    await bot.api.sendMessage(chatId, message);
    console.log("Message sent!");
  } catch (err) {
    console.error("Error sending message:", err);
  }
}

module.exports = {
  bot,
  sendMessage
};

