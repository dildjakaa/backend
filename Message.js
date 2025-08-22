const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  username: String,
  text: String,
  chatId: { type: String, required: true }, // ID чата между двумя пользователями
  timestamp: { type: Date, default: Date.now }
});

// Индекс для быстрого поиска сообщений по chatId
MessageSchema.index({ chatId: 1, timestamp: 1 });

module.exports = mongoose.model('Message', MessageSchema);


