const { body, params} = require('express-validator')

module.exports = {
    EMAIL: body('email').trim().notEmpty().withMessage('Email is required!').bail(),
    PASSWORD: body('password').trim().notEmpty().withMessage('Password is required!').bail(),
    NAME: body('name').trim().notEmpty().withMessage('Name is required!').bail(),
    PHONENO: body('phoneNo').trim().notEmpty().withMessage('Phone number is required!').bail(),
    CURRENTPASSWORD: body('password').trim().notEmpty().withMessage('Current password is required!').bail(),
    CONFIRMPASSWORD: body('password').trim().notEmpty().withMessage('Confirm password is required!').bail(),
}