const { check, body } = require('express-validator/check');

const User = require('../models/user');
const Product = require('../models/product');

exports.signupValidator = () => {
    return [
        check('email')
            .isEmail()
            .withMessage('Please enter valid email')
            .custom((value, { req }) => {
                // if(value === 'shivangigarambha@gmail.com') {
                //     throw new Error('This email is forbidden.');
                // }
                // return true;
                return User
                    .findOne({email: value})
                    .then(userDoc => {
                        if(userDoc) {
                            return Promise.reject('Email already exist!')
                            // here we use promise bcz finding user from database is not an instant task, it will take some time
                            // so rather than registering this task and going ahead, promise will wait untill this task done
                        }
                    })
            })
            .normalizeEmail(),  
        // body('password', 'Enter password with only numbers and text and at least 5 characters') // to print general error message
        body('password')
            .isLength({min: 5})
            .withMessage('Enter password with at least 5 characters.')
            .isAlphanumeric()
            .withMessage('Enter password with only numbers and text.')
            .trim(),
        body('confirmPassword')
            .custom((value, {req}) => {
                if(value !== req.body.password) {
                    throw new Error('Passwords have to match!');
                }
                return true;
            })
            .trim()
    ]
} 

exports.loginValidator = () => {
    return [
        check('email')
            .isEmail()
            .withMessage('Please Enter valid Email')
            .normalizeEmail(),
        body('password')
            .isLength({min: 5})
            .withMessage('Enter password with at least 5 characters.')
            .trim()
    ]

}

exports.addProductValidator = () => {
    return [
        body('title')
            .isString()
            .isLength({min: 3})
            .trim(),
        body('price').isFloat(),
        body('description')
            .isLength({min: 3, max: 200})
            .trim()
    ]
}