const path = require('path');

const express = require('express');

const adminController = require('../controllers/admin');
const isAuth = require('../middleware/is-auth');
const validator = require('../middleware/validator');

const router = express.Router();

// /admin/add-product => GET
router.get('/add-product', isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get('/products', isAuth,  adminController.getProducts);

// /admin/add-product => POST
router.post('/add-product', 
    validator.addProductValidator(), 
    isAuth,  
    adminController.postAddProduct
);

router.get('/edit-product/:productId', isAuth,  adminController.getEditProduct);

router.post('/edit-product', 
    validator.addProductValidator(), 
    isAuth,  
    adminController.postEditProduct
);

router.delete('/product/:productId', isAuth,  adminController.deleteProduct);

module.exports = router;
