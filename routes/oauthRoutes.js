const express = require('express');
const router = express.Router();
const {
  registerClient,
  showAuthorizePage,
  submitAuthorizePage,
  issueToken,
  handleDirectGoogleLogin,
  handleGoogleCallback
} = require('../controllers/oauthController');

router.post('/register', registerClient);
router.get('/authorize', showAuthorizePage);
router.post('/authorize', submitAuthorizePage);
router.post('/token', issueToken);
router.get('/google-direct', handleDirectGoogleLogin);
router.get('/google-callback', handleGoogleCallback);

module.exports = router;
