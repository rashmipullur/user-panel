const express = require('express')
const multer = require('multer')
const User = require('../models/user')
const userControllers = require('../controllers/user.controller')
const authUser = require('../middleware/auth')
const router = new express.Router()
const { validate } = require('../validator/express.validator')
const { validateReq } = require('../../public/utils')
const passport = require('passport')

router.post('/register', validate('registerUser'), validateReq, userControllers.registerUser)
router.post('/verifyEmail/:userid/:token', userControllers.verifyUserEmail)
router.post('/login', validate('loginUser'), validateReq, userControllers.loginUser)
router.post('/logout', authUser, userControllers.logoutUser)

router.get('/me', authUser, userControllers.readUser)

router.patch('/updateUser', authUser, userControllers.updateProfile)

router.post('/updateAvatar', authUser , userControllers.updateAvatar)


// forgot password 
router.post('/sendForgotPasswordLink', validate('sendForgotPasswordLink'), validateReq, userControllers.sendResetPasswordLink)
router.post('/forgotPassword/:id', validate('forgotPassword'), validateReq, userControllers.forgotPassword)
router.post('/resetPassword', validate('resetPassword'), validateReq, authUser, userControllers.resetPassword)

module.exports = router