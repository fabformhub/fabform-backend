import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables from .env

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

// Check if token is defined
if (!TELEGRAM_BOT_TOKEN) {
  throw new Error('TELEGRAM_BOT_TOKEN is not defined in .env');
}

export async function sendMessage(chatId, message) {
  try {
    const response = await axios.post(`${TELEGRAM_API_URL}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'Markdown' // Optional: use Markdown for formatting
    });

    console.log('Message sent:', response.data);
    return { success: true, data: response.data };
  } catch (err) {
    console.error('Error sending message:', err);
    return { success: false, error: err };
  }
}
