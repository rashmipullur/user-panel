const nodemailer = require('nodemailer')
const { hashSync, compareSync } = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/user')
const UserSession = require('../models/userSession.model')
const HTTP = require('../../constants/responseCode.constant')
const { encryptUserModel, createSessionAndJwtToken } = require('../../public/utils')
const { sendWelcomeEmail, sendOTPEmail, sendVerifyEmail } = require('../emails/account')

const registerUser = async (req, res) => {
    //const user = new User(req.body)
    try {
        const { email, password, name, phoneNo} = req.body
        const encData = await encryptUserModel({ email })
        const existsUser = await User.findOne({ email: encData.email })
        if (existsUser && existsUser.isVerified === true) {
            return res.status(200).send({ 'status': false, 'code': HTTP.CONFLICT ,'message': 'Email already taken', 'data': {} })
        } else if (existsUser && existsUser.isVerified === false) {
            // await user.save()
            // sendWelcomeEmail(user.email, user.name)
            // const token = await user.generateAuthToken()
            // res.status(201).send({user, token})
            
            const secret = process.env.JWT_SECRET + existsUser.password
            const payload = {
                id: existsUser._id,
                email: existsUser.email,
                name: existsUser.name,
                phoneNo: existsUser.phoneNo
            }
            const token = jwt.sign(payload, secret, { expiresIn: '15m' })
            const link = `localhost:3000/verify-email/${existsUser._id}/${token}`
            console.log("verification link -> ", link)
            sendVerifyEmail(existsUser, link)
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'Please check your email.', 'data': {} })
        } else {
            const user = new User({
                email,
                password: hashSync(password.trim(), 8),
                name,
                phoneNo
            })
            const userData = await user.save()

            if (!userData) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST ,'message': 'Unable to store user.', 'data': {} })
            }

            //decrypt data
            user.decryptFieldsSync({ __secret__: process.env.DATABASE_ACCESS_KEY })
            const secret = process.env.JWT_SECRET + user.password
            const payload = {
                id: user._id,
                email: user.email,
                name: user.name,
                phoneNo: user.phoneNo
            }
            const token = jwt.sign(payload, secret, { expiresIn: '15m' })
            const link = `localhost:3000/verify-email/${user._id}/${token}`
            console.log("verification link -> ", link)
            sendVerifyEmail(user, link)
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'Please check your email.', 'data': {} })
        }
    } catch(e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const verifyUserEmail = async (req, res) => {
    try {
        const { userid, token } = req.params
        if(!userid || !token) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_FOUND, 'message': 'Something went wrong!', data: {} }) 
        }
        const existsUser = await User.findOne({_id: userid, isVerified: false})
        if (!existsUser) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.CONFLICT, 'message': 'User already verified!', data: {} })
        } else {
            try {
                const secret = process.env.JWT_SECRET + existsUser.password
                const isTokenVerified = jwt.verify(token, secret)
                const userData = await User.findOneAndUpdate({ _id: userid, isVerified: false }, { isVerified: true }, { new: true })
                if(!userData) {
                    return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Unable to store data!', data: {} })
                }

                // generate JWT token and session here 
                const authToken = await createSessionAndJwtToken(userData)
                return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'Verification Successful!', 'data': {
                    userData: {
                        id: userData._id,
                        email: userData.email,
                        name: userData.name,
                        phoneNo: userData.phoneNo
                    },
                    token: "Bearer " + authToken
                } })
                

            } catch (e) {
                console.log(e)
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Verification link has expired!', data: {} })
            }
        }
    } catch(e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const loginUser = async (req, res) => {
    // try {
    //     const user = await User.findByCredentials(req.body.email, req.body.password)
    //     const token = await user.generateAuthToken()
    //     res.send({ user, token })
        
    // } catch(e) {
    //     res.status(400).send({'message': 'Invalid details'})
    // }

    try {
        const { email, password } = req.body
        const encData = await encryptUserModel({ email })
        const user = await User.findOne({ email: encData.email })

        if (!user) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, 'message': 'Email or password is incorrect!', data: {} })
        }
        if (user.password === undefined || !compareSync(password, user.password)) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, 'message': 'Email or password is incorrect!', data: {} })
        }

        // jwt token and store session data

        const token = await createSessionAndJwtToken(user)
        return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'Logged In Successfully!', 'data': {
            userData: {
                id: userData._id,
                email: userData.email,
                name: userData.name,
                phoneNo: userData.phoneNo
            },
            token: "Bearer " + authToken
        } })


    } catch(e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const logoutUser = async (req, res) => {
    // try {
    //     req.user.tokens = []
    //     await req.user.save()
    //     res.send()
    // } catch(e) {
    //     res.status(500).send({'message': 'Something went wrong'})
    // }

    try {
        if (req.user) {
            const userData = await UserSession.findOneAndUpdate({ _id: req.user.sessionId, userid: req.user._id, isActive: true }, { isActive: false }, { new: true})
            if (!userData) {
                return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, 'message': 'User session is invalid', data: {} })
            }
            return res.status(HTTP.SUCCESS).send({ "status": true, 'code': HTTP.SUCCESS, 'message': 'User logged out successfully', data: {} })
        } else {
            return res.status(HTTP.BAD_REQUEST).send({ "status": false, 'code': HTTP.BAD_REQUEST, 'message': 'Please authenticate', data: {} })
        }
    } catch(e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const readUser = async (req, res) => {
    res.send(req.user)
}

const updateUser = async (req, res) => {
    const updates = Object.keys(req.body)
    const allowedUpdates = ['name','phoneNo']
    const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

    if (!isValidOperation) {
        return res.status(400).send({ error: 'Invalid updates!' })
    }

    try {
        updates.forEach((update) => req.user[update] = req.body[update])
        await req.user.save() 
        res.send(req.user)
    } catch(e) {
        res.status(400).send({ 'status': false, 'message': 'Something went wrong!', data: {} })
    }
}

let otp 
const sendResetPasswordLink = async (req, res) => {
    const email = req.body.email
    console.log(email)
    try {
        otp = Math.random()
        otp = otp * 1000000
        otp = parseInt(otp)

        var transport = nodemailer.createTransport({
            host: "smtp.mailtrap.io",
            port: 2525,
            auth: {
            user: "e11d19bc3faffe",
            pass: "524f075ca3a596"
            }
            })
        
        transport.sendMail({
            from: 'rashmipullur1@gmail.com',
            to: email,
            subject: 'Otp for registration is:',
            html: "<h3>OTP for account verification is </h3>" + "<h1 style='font-weight:bold;'>" + otp + "</h1>", // html body
            text: `hello.` // template string
        }, function(err, info) {
            if (err) {
              console.log(err)
            } else {
              console.log(info)
              res.render('otp')
            }
         })

        //sendOTPEmail(req.user.email, req.user.name)
        res.send('Check email, verify and change password')
    } catch(e) {
        res.status(500).send(e)
    }
}

const verifyUser = async (req, res) => {
    try {
        if (req.body.otp == otp) {
            res.send("Verification Successful!")
        } else {
            res.send("Invalid OTP!")
        }
    } catch(e) {
        res.status(500).send(e)
    }
}

const forgotPassword = async (req, res) => {
    try {
        const { id } = req.params
        if (req.body.password === req.body.confirmPassword) {
            const passwordHash = bcrypt.hashSync(req.body.password, 8)
            await User.updateOne(
                { "_id" : id},
                { $set: {"password": passwordHash} }
            )
            //await req.user.save()
            res.send(req.user)
        } else {
            res.send("Passwords don't match")
        }
    } catch(e) {
        res.status(400).send(e) 
    }
}

const resetPassword = async (req, res) => {
    try {
        if (req.body.password === req.body.confirmPassword) {
            const passwordHash = bcrypt.hashSync(req.body.password, 8)
            await User.updateOne(
                { "_id" : req.user._id},
                { $set: {"password": passwordHash} }
            )
            res.send(req.user)
        } else {
            res.send("Passwords don't match")
        }
    } catch(e) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const uploadAvatar = async (req, res) => {
    try {
        req.user.avatar = req.file.buffer
        await req.user.save()
        res.send()
    } catch (e) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

const updateAvatar = async (req, res) => {
    try {
        req.user.avatar = req.file.buffer
        await req.user.save()
        res.send()
    } catch (e) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
    }
}

module.exports = {
    registerUser,
    verifyUserEmail,
    loginUser,
    logoutUser,
    readUser,
    updateUser,
    sendResetPasswordLink,
    verifyUser,
    forgotPassword,
    resetPassword,
    uploadAvatar,
    updateAvatar
}