const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator/check');

const User = require('../models/user');

const transport = nodemailer.createTransport({
  host: "smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "809d33194b3932",
    pass: "314ed0161941b1"
  }
});

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else message = null;  
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
    },
    validationErrors: []
  });
};  

exports.postLogin = (req, res, next) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: req.body.email,
        password: req.body.password,
      },
      validationErrors: errors.array()
    });
  }
  User.findOne({email: req.body.email})
    .then(user => {
      if(!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid username or password',
          oldInput: {
            email: req.body.email,
            password: req.body.password,
          },
          validationErrors: errors.array()
        });
      }
      bcrypt
        .compare(req.body.password, user.password)
        .then(doMatch => {
          if(doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          req.flash('error', 'Invalid Username or Password!');
          res.redirect('/login');
        })
        .catch(err => {
          console.log(err);
          return res.redirect('/login');
      })
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else message = null;  
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'SignUp',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: ''
    },
    validationErrors: []
  });
};

exports.postSignup = (req, res, next) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
   return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'SignUp',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: req.body.email,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    });
  }
  bcrypt
    .hash(req.body.password, 12)
    .then(encryptedPassword => {
      const user = new User({
        email: req.body.email,
        password: encryptedPassword,
        cart: { items: [] }
      })
      return user.save();
    })
    .then(result => {
      res.redirect('/login');
      return transport.sendMail({
        to: req.body.email,
        from: 'test@test.com',
        subject: 'Signup Successful',
        html: '<h1>You Successfully signed up!</h1>'
      })
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else message = null;  
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
}; 

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if(err) {
      console.log(err);
      return res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({email: req.body.email})
      .then(user => {
        if(!user) {
          req.flash('error', 'No account found with that email!');
          return res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then(result => {
        res.redirect('/');
        transport.sendMail({
          to: req.body.email,
          from: 'test@test.com',
          subject: 'Password Reset',
          html: `
            <p>You requested a password reset</p> 
            <p>Click this <a href="http://localhost:3000/new-password/${token}">link</a> to set new password</p> 
          `
        })
      })
      .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      });
  })
}

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({resetToken: token, resetTokenExpiration: {$gt: Date.now()}})
    .then(user => {
      if(!user) {
        req.flash('error', 'No request Found or Request TimeOut!');
        return res.redirect('/reset');
      }
      let message = req.flash('error');
      if(message.length > 0) {
        message = message[0];
      } else message = null;  
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: req.params.token
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
}

exports.postNewPassword = (req, res, next) => {
  let resetUser;
  User.findOne({
    resetToken: req.body.passwordToken,
    resetTokenExpiration : {$gt: Date.now()},
    _id: req.body.userId
  })
    .then(user => {
      if(!user) {
        req.flash('error', 'No request Found or Request TimeOut!');
        return res.redirect('/reset');
      }
      resetUser = user;
      return bcrypt.hash(req.body.password, 12);
    })
    .then(hashedPassword => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(result => {
      console.log('Password Updated');
      res.redirect('/login');
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
}