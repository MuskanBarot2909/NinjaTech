// ticketRoutes.js
const express = require('express');
const router = express.Router();
const ticketController = require('../controllers/ticketController');
const verifyTokenAndRole = require('../middlewares/authMiddleware');

// Login
router.post('/login', ticketController.login);

// Register
router.post('/register', ticketController.register);

// Create Ticket
router.post('/ticket', verifyTokenAndRole(['client']), ticketController.createTicket);

// Add Remark
router.put('/ticket/:id/add-remark', verifyTokenAndRole(['employee']), ticketController.addRemark);

// Manager Actions
router.put('/ticket/:id/manager-actions', verifyTokenAndRole(['manager']), ticketController.managerActions);

// Admin Actions
router.put('/ticket/:id/admin-actions', verifyTokenAndRole(['admin']), ticketController.adminActions);

// Employee Resubmit
router.put('/ticket/:id/employeeresubmit', verifyTokenAndRole(['employee']), ticketController.employeeResubmit);

// Manager Resubmit
router.put('/ticket/:id/managerresubmit', verifyTokenAndRole(['manager']), ticketController.managerResubmit);

// View Ticket Stages
router.get('/ticket/:id/stages', verifyTokenAndRole(['admin']), ticketController.viewTicketStages); // Changed to viewTicketStages

// Add Admin Remark
router.put('/ticket/:id/add-admin-remark', verifyTokenAndRole(['admin']), ticketController.addAdminRemark);

module.exports = router;
