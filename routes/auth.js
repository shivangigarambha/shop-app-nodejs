const express = require('express');
const { check } = require('express-validator/check');

const authController = require('../controllers/auth');
const validator = require('../middleware/validator');

const router = express.Router();

router.get('/login', authController.getLogin);

router.post('/login',
    validator.loginValidator(),
    authController.postLogin
);

router.get('/signup', authController.getSignup);

router.post('/signup',  
    validator.signupValidator(), 
    authController.postSignup
);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/new-password/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;