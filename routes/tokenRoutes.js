const express = require('express');
const router = express.Router();
const { generateToken, listTokens, revokeToken } = require('../controllers/tokenController');
const { authenticateUser } = require('../middleware/auth');

// All token management routes require user JWT authentication
router.use(authenticateUser);

router.post('/generate', generateToken);
router.get('/', listTokens);
router.delete('/:id', revokeToken);

module.exports = router;
