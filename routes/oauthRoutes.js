const express = require('express');
const router = express.Router();
const { registerClient, showAuthorizePage, submitAuthorizePage, issueToken } = require('../controllers/oauthController');

router.post('/register', registerClient);
router.get('/authorize', showAuthorizePage);
router.post('/authorize', submitAuthorizePage);
router.post('/token', issueToken);

module.exports = router;
