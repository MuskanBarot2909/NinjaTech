const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt=require('bcrypt');

const app = express();
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/ticketing', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const secretKey = 'your_secret_key';

const roles = ['admin', 'manager', 'employee', 'client'];

const ticketSchema = new mongoose.Schema({
    text: String,
    images: [String],
    videos: [String],
    remarks: [{ role: String, text: String }],
    status: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Reference to the User model
  });

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    role: String,
    token: String // Add token field
  });

const Ticket = mongoose.model('Ticket', ticketSchema);
const User=mongoose.model('User',userSchema);

function verifyTokenAndRole(roles) {
  return (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
      return res.status(401).json({ message: 'Authorization token is required' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }

      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Unauthorized role' });
      }

      req.user = decoded;
      next();
    });
  };
}

app.post('/register', async (req, res) => {
    try {
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword, role });
      await user.save();
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to register user', error: error.message });
    }
  });

  app.post('/login', async (req, res) => {
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
      user.token = token; // Save token in database
      await user.save();
      res.json({ token });
    } catch (error) {
      res.status(500).json({ message: 'Failed to login', error: error.message });
    }
  });

  app.post('/ticket', verifyTokenAndRole(['client']), async (req, res) => {
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
        createdBy: user._id // Assuming req.user contains the user information
      });
      await ticket.save();
      res.json({ message: 'Ticket created successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to create ticket', error: error.message });
    }
  });

app.put('/ticket/:id/add-remark', verifyTokenAndRole(['employee']), async (req, res) => {
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
});

// Define other routes for manager, admin actions (approve/disapprove, add remarks)
// Define route for employee to resubmit the ticket after making necessary changes
app.put('/ticket/:id/employeeresubmit', verifyTokenAndRole(['employee']), async (req, res) => {
    try {
      const ticket = await Ticket.findById(req.params.id);
      if (!ticket) {
        return res.status(404).json({ message: 'Ticket not found' });
      }
  
      if (ticket.status !== 'Rejected By Manager') {
        return res.status(400).json({ message: 'Ticket can only be resubmitted if it is rejected' });
      }
  
      // Update ticket status and clear previous remarks
      ticket.status = 'Pending Approval';
      ticket.remarks = [];
      await ticket.save();
  
      res.json({ message: 'Ticket resubmitted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to resubmit ticket', error: error.message });
    }
  });

  app.put('/ticket/:id/managerresubmit', verifyTokenAndRole(['Manager']), async (req, res) => {
    try {
      const ticket = await Ticket.findById(req.params.id);
      if (!ticket) {
        return res.status(404).json({ message: 'Ticket not found' });
      }
  
      if (ticket.status !== 'Rejected By Admin') {
        return res.status(400).json({ message: 'Ticket can only be resubmitted if it is rejected' });
      }
  
      // Update ticket status and clear previous remarks
      ticket.status = 'Pending Approval';
      ticket.remarks = [];
      await ticket.save();
  
      res.json({ message: 'Ticket resubmitted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to resubmit ticket', error: error.message });
    }
  });
  
  // Define route for viewing all stages of a ticket by admin
  app.get('/ticket/:id/stages', verifyTokenAndRole(['admin']), async (req, res) => {
    try {
      const ticket = await Ticket.findById(req.params.id);
      if (!ticket) {
        return res.status(404).json({ message: 'Ticket not found' });
      }
  
      res.json({ stages: ticket.remarks });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch ticket stages', error: error.message });
    }
  });
  
  
  
  // Define routes for admin actions

 
  
  app.put('/ticket/:id/add-admin-remark', verifyTokenAndRole(['admin']), async (req, res) => {
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
  });
  
 // Define route for manager to add remarks, approve or disapprove the ticket
 app.put('/ticket/:id/manager-actions', verifyTokenAndRole(['manager']), async (req, res) => {
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
});

app.put('/ticket/:id/admin-actions', verifyTokenAndRole(['admin']), async (req, res) => {
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
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
