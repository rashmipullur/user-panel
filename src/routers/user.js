const express = require('express')
const multer = require('multer')
const User = require('../models/user')
const userControllers = require('../controllers/user.controller')
const auth = require('../middleware/auth')
const router = new express.Router()
const { validate } = require('../validator/express.validator')

router.post('/register', validate("registerUser"), userControllers.registerUser)
router.post('/verifyEmail/:userid/:token', userControllers.verifyUserEmail)
router.post('/users/login', validate("loginUser"), userControllers.loginUser)
router.post('/users/logout', auth, userControllers.logoutUser)
router.get('/users/me', auth, userControllers.readUser)

router.patch('/users/me', validate("updateUser"), auth, userControllers.updateUser)

const upload = multer({
   // dest: 'avatars',
    limits: {
        fileSize: 1000000
    },
    fileFilter(req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
            return cb(new Error('Please upload an image'))
        }
        cb(undefined, true)
    }
})
router.post('/users/me/avatar', auth, upload.single('avatar'), async (req, res) => {
    req.user.avatar = req.file.buffer
    await req.user.save()
    res.send()
}, (error, req, res, next) => {
    res.status(400).send({ error: error.message })
})

router.patch('/users/me/avatar/update', auth, upload.single('avatar'), async (req, res) => {
    req.user.avatar = req.file.buffer
    await req.user.save()
    res.send()
}, (error, req, res, next) => {
    res.status(400).send({ error: error.message })
})

// forgot password 
router.post('/sendForgotPasswordLink', validate("sendForgotPasswordLink"),userControllers.sendResetPasswordLink)
router.post('/verifyUser', userControllers.verifyUser)
router.patch('/forgotPassword/:id', userControllers.forgotPassword)

router.patch('/users/me/resetPassword', auth, userControllers.resetPassword)

module.exports = router