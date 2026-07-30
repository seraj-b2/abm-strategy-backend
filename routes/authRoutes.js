const express = require('express');
const router = express.Router();
const { googleAuth, getMe, devLogin } = require('../controllers/authController');
const { authenticateUser } = require('../middleware/auth');

// Public route for Google Auth login/signup
router.post('/google', googleAuth);

// Public dev login route (only works in non-production)
router.post('/dev-login', devLogin);

// Protected route to get user profile
router.get('/me', authenticateUser, getMe);

module.exports = router;
