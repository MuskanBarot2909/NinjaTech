const mongoose = require('mongoose');

const ticketSchema = new mongoose.Schema({
    text: String,
    images: [String],
    videos: [String],
    remarks: [{ role: String, text: String }],
    status: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Reference to the User model
});

const Ticket = mongoose.model('Ticket', ticketSchema);

module.exports = Ticket;
