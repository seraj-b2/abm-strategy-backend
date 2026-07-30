const express = require('express');
const router = express.Router();
const { verifyToken } = require('../controllers/mcpController');

// Token verification endpoint for external MCP server instances
router.post('/verify-token', verifyToken);

module.exports = router;
