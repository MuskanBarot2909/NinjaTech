const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/userModel');
const Ticket = require('../models/ticketModel');

const secretKey = 'your_secret_key';

exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        const token = jwt.sign({ username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
        user.token = token;
        await user.save();
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Failed to login', error: error.message });
    }
};

exports.register = async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword, role });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to register user', error: error.message });
    }
};

exports.createTicket = async (req, res) => {
    try {
        const token = req.headers['authorization'];
        const user = await User.findOne({ token });
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }
        const { text, images, videos } = req.body;
        const ticket = new Ticket({
            text,
            images,
            videos,
            remarks: [],
            status: 'Pending Approval',
            createdBy: user._id
        });
        await ticket.save();
        res.json({ message: 'Ticket created successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to create ticket', error: error.message });
    }
};

exports.addRemark = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        ticket.remarks.push({ role: 'employee', text: req.body.remark });
        await ticket.save();
        res.json({ message: 'Remark added successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to add remark', error: error.message });
    }
};

exports.managerActions = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        const { action, remark } = req.body;
        if (action !== 'approve' && action !== 'disapprove') {
            return res.status(400).json({ message: 'Invalid action. Valid actions are "approve" or "disapprove"' });
        }

        if (action === 'approve') {
            ticket.remarks.push({ role: 'manager', text: 'Ticket approved by manager' });
            ticket.status = 'Approved by Manager';
            // Notify admin
            // Implement notification logic here
        } else {
            ticket.remarks.push({ role: 'manager', text: remark });
            ticket.status = 'Rejected by Manager';
            ticket.remarks.push({ role: 'manager', text: 'Ticket returned to employee for necessary changes' });
            // Notify employee and provide feedback
            // Implement notification logic here
        }

        await ticket.save();
        res.json({ message: `Ticket ${action === 'approve' ? 'approved' : 'disapproved'} by manager` });

    } catch (error) {
        res.status(500).json({ message: 'Failed to perform manager action', error: error.message });
    }
};

exports.adminActions = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        const { action, remark } = req.body;
        if (action !== 'approve' && action !== 'disapprove') {
            return res.status(400).json({ message: 'Invalid action. Valid actions are "approve" or "disapprove"' });
        }

        if (action === 'approve') {
            ticket.remarks.push({ role: 'admin', text: 'Ticket approved by admin' });
            ticket.status = 'Approved by Admin';
            // Notify client
            // Implement notification logic here
        } else {
            ticket.remarks.push({ role: 'admin', text: remark });
            ticket.status = 'Rejected by Admin';
            ticket.remarks.push({ role: 'admin', text: 'Ticket returned to employee for necessary changes' });
            // Notify employee and provide feedback
            // Implement notification logic here
        }

        await ticket.save();
        res.json({ message: `Ticket ${action === 'approve' ? 'approved' : 'disapproved'} by admin` });

    } catch (error) {
        res.status(500).json({ message: 'Failed to perform admin action', error: error.message });
    }
};

exports.employeeResubmit = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        if (ticket.status !== 'Rejected by Manager') {
            return res.status(400).json({ message: 'Ticket can only be resubmitted if it is rejected' });
        }

        ticket.status = 'Pending Approval';
        ticket.remarks = [];
        await ticket.save();

        res.json({ message: 'Ticket resubmitted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to resubmit ticket', error: error.message });
    }
};

exports.managerResubmit = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        if (ticket.status !== 'Rejected by Admin') {
            return res.status(400).json({ message: 'Ticket can only be resubmitted if it is rejected by admin' });
        }

        ticket.status = 'Pending Approval';
        ticket.remarks = [];
        await ticket.save();

        res.json({ message: 'Ticket resubmitted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to resubmit ticket', error: error.message });
    }
};

exports.viewTicketStages = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        res.json({ stages: ticket.remarks });
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch ticket stages', error: error.message });
    }
};

exports.addAdminRemark = async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ message: 'Ticket not found' });
        }

        ticket.remarks.push({ role: 'admin', text: req.body.remark });
        await ticket.save();

        res.json({ message: 'Admin remark added successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to add admin remark', error: error.message });
    }
};
