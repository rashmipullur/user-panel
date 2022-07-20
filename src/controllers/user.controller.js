const nodemailer = require('nodemailer')
const { hashSync, compareSync } = require('bcryptjs')
const jwt = require('jsonwebtoken')
const multer = require('multer')
const User = require('../models/user')
const UserSession = require('../models/userSession.model')
const HTTP = require('../../constants/responseCode.constant')

const { encryptUserModel, createSessionAndJwtToken, formateUserData } = require('../../public/utils')
const { sendWelcomeEmail, sendOTPEmail, sendVerifyEmail, sendForgotPasswordLink } = require('../emails/account')


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
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                phoneNo: user.phoneNo
            },
            token: "Bearer " + token
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

// const updateUser = async (req, res) => {
//     const updates = Object.keys(req.body)
//     const allowedUpdates = ['name','phoneNo']
//     const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

//     if (!isValidOperation) {
//         return res.status(HTTP.BAD_REQUEST).send({ error: 'Invalid updates!' })
//     }

//     try {
//         updates.forEach((update) => req.user[update] = req.body[update])
//         await req.user.save() 
//         res.send(req.user)
//     } catch(e) {
//         res.status(HTTP.BAD_REQUEST).send({ 'status': false, 'message': 'Something went wrong!', data: {} })
//     }
// }

async function updateProfile(req, res) {
    try {
        const updates = Object.entries(req.body)
        if (updates.length === 0) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": "No changes available for update!", data: {} })
        }

        const allowedUpdates = ['name','phoneNo']

        // const isValidOperation = updates.every((updates) => {
        //     if (allowedUpdates.includes(updates[0])) {
        //         if (updates[0] === "name" && updates[1].toString().length <= 0) {
        //             return false
        //         }
        //         return true
        //     } else {
        //         return false
        //     }
        // })

        const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

        if (!isValidOperation) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": "Update is not allowed!", data: {} })
        }

        var dataRecord = {
            ...req.body
        }

        encData = await encryptUserModel(dataRecord)

        for (const key in dataRecord) {
            dataRecord[key] = encData[key]
        }

        await User.findByIdAndUpdate({ _id: req.user._id }, dataRecord, { new: true }).then(async (userinfo) => {

            userinfo = await formateUserData(userinfo)
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, "message": "Profile updated successfully!", data: userinfo })
        }).catch(e => {
            console.log(e)
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
        })

    } catch (e) {
        console.log(e)
        var errObj = "Something went wrong!"
        if (e.message) {
            errObj = Object.values(errorFormatter(e.message))[0] == undefined ? errObj : errorFormatter(e.message)
        }
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": errObj, data: {} })
    }
}

// let otp 
const sendResetPasswordLink = async (req, res) => {
    // const email = req.body.email
    // console.log(email)
    // try {
    //     otp = Math.random()
    //     otp = otp * 1000000
    //     otp = parseInt(otp)

    //     var transport = nodemailer.createTransport({
    //         host: "smtp.mailtrap.io",
    //         port: 2525,
    //         auth: {
    //         user: "e11d19bc3faffe",
    //         pass: "524f075ca3a596"
    //         }
    //         })
        
    //     transport.sendMail({
    //         from: 'rashmipullur1@gmail.com',
    //         to: email,
    //         subject: 'Otp for registration is:',
    //         html: "<h3>OTP for account verification is </h3>" + "<h1 style='font-weight:bold;'>" + otp + "</h1>", // html body
    //         text: `hello.` // template string
    //     }, function(err, info) {
    //         if (err) {
    //           console.log(err)
    //         } else {
    //           console.log(info)
    //           res.render('otp')
    //         }
    //      })

    //     // sendOTPEmail(req.user.email, req.user.name)
    //     res.send('Check email, verify and change password')
    // } catch(e) {
    //     res.status(500).send(e)
    // }

    try {
        const { email } = req.body
        const encData = await encryptUserModel({ email })

        const user = await User.findOne({ email: encData.email })
        if (!user) { 
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST ,'message': 'Email doesnt exist!', 'data': {} }) 
        } else {
            // decrypt data
            user.decryptFieldsSync({ __secret__: process.env.DATABASE_ACCESS_KEY })
            const secret = process.env.JWT_SECRET + user.password
            const payload = {
                id: user._id,
                email: user.email,
                name: user.name,
                phoneNo: user.phoneNo
            }
            const token = jwt.sign(payload, secret, { expiresIn: '15m' })
            const link = `localhost:3000/reset-password/${user._id}/${token}`
            console.log("link -> ", link)
            sendForgotPasswordLink(user.email, link).then((val) => {
                return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.CONFLICT ,'message': 'Please check your email to change password', 'data': val }) 
            }).catch((e) => {
                console.log(e)
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST ,'message': 'Unable to send email.', 'data': {} }) 
            })
        }

    } catch(e) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR,'message': 'Something went wrong.', 'data': {} }) 
    }

}


const forgotPassword = async (req, res) => {
    
    const { id, token } = req.params
    const { password, confirmPassword } = req.body
   
    if (!id || !token || !password || !confirmPassword) { return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST,'message': 'Password and Confirm password is required!', 'data': {} }) }

    if(password !== confirmPassword) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST,'message': 'Passwords does not match', 'data': {} })
    } else {
        try {
            User.findOne({ _id: id}, async (err, user) => {
                if (!user) {
                    return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST,'message': 'Enter valid credentials', 'data': {} })  
                } else {
                    const secret = process.env.JWT_SECRET + user.password
                    try {
                        const payload = jwt.verify(token, secret)
                        const hashedPassword = hashSync(password.trim(), 8)
                        user.password = hashedPassword
                        await user.save()
                        return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS ,'message': 'Password updated successfully', 'data': {} })
                    } catch (e) {
                        console.log(e)
                        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST ,'message': 'Password link has expired', 'data': {} })
                    }
                }
            })
        } catch(e) {
            console.log(e)
            var errObj = "Something went wrong!"
            if (e.message) {
                errObj = Object.values(errorFormatter(e.message))[0] == undefined ? errObj : errorFormatter(e.message)
            }
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR,'message': errObj, 'data': {} })
        }
    }

}

// const resetPassword = async (req, res) => {
//     try {
//         if (req.body.password === req.body.confirmPassword) {
//             const passwordHash = bcrypt.hashSync(req.body.password, 8)
//             await User.updateOne(
//                 { "_id" : req.user._id},
//                 { $set: {"password": passwordHash} }
//             )
//             res.send(req.user)
//         } else {
//             res.send("Passwords don't match")
//         }
//     } catch(e) {
//         return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
//     }
// }

async function resetPassword (req, res) {
    try {
        const { currentPassword, password, confirmPassword } = req.body

        if (password !== confirmPassword) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": 'Password and confirm password does not match.', data: {} })
        } else if (password === currentPassword) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": 'Password cannot be same as current password.', data: {} })
        }

        User.findOne({ _id: req.user }, async (err, user) => {
            if (user) {
                const passwordMatch = compareSync(currentPassword, user.password)
                if (!passwordMatch) {
                    return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.SUCCESS, "message": 'Current Password is invalid', data: {} })
                }
                user.password = hashSync(password, 8)
                await user.save().then(async (userinfo) => {
                    userinfo = await formateUserData(userinfo)
                    return res.status(HTTP.SUCCESS).send({ "status": true, 'code': HTTP.SUCCESS, "message": 'password updated successfully', data: userinfo })
                })
            } else {
                return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.NOT_FOUND, "message": 'User does not exist.', data: {} })
            }
        })
    } catch(e) {
        console.log(e)
        var errObj = "Something went wrong!"
        if (e.message) {
            errObj = Object.values(errorFormatter(e.message))[0] == undefined ? errObj : errorFormatter(e.message)
        }
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR,'message': errObj, 'data': {} })
    }
}



const updateAvatar = async (req, res) => {
    try {
        console.log(req.file);
    } catch(e) {
        res.status(400).send({ 'status': false, 'message': 'Something went wrong!', data: {} })
    }
}

// const uploadAvatar = async (req, res) => {
//     try {
//         req.user.avatar = req.file.buffer
//         await req.user.save()
//         res.send()
//     } catch (e) {
//         return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
//     }
// }

// const updateAvatar = async (req, res) => {
//     try {
//         req.user.avatar = req.file.buffer
//         await req.user.save()
//         res.send()
//     } catch (e) {
//         return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.INTERNAL_SERVER_ERROR, 'message': 'Something went wrong!', data: {} })
//     }
// }

// async function updateAvatar (req, res) {
//     try {
//         uploadAvatar(req, res, async function(error) {
//             if (error) {
//                 if (error.code ==  'LIMIT_FILE_SIZE') {
//                     return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": "File Size is too large. Allowed file size is 1mb", data: {} })
//                 }
//             }

//             if (req.fileValidationError) {
//                 return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": req.fileValidationError, data: {} })
//             }

//             if (req.file === undefined) {
//                 return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": "Please select an image!", data: {} })
//             }

//             const avatar = await req.file.key

//             const _id = req.user._id.toString()
//             const user = await User.findOne({ _id })
//             if(!user) {
//                 await deleteObject(avatar, res)
//                 return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.NOT_FOUND, "message": "User does not exist!", data: {} })
//             }
//             const oldAvatar = await user.avatar
//             user.avatar = avatar

//             await user.save().then(async (userinfo) => {
//                 userinfo.decryptFieldsSync({ __secret__: process.env.DATABASE_ACCESS_KEY })
//                 userinfo = await formateUserData(userinfo)
//                 const key = oldAvatar
//                 if(key && key !== "avatar/profile-pic.jpg") {
//                     await deleteObject(key, res)
//                     return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.SUCCESS, "message": "new image uploaded", data: {} })
//                 } else {
//                     return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.SUCCESS, "message": "new image uploaded", data: {} })
//                 }
//             })
//         })
//     } catch(e) {
//         console.log(e)
        
//     }
// }

module.exports = {
    registerUser,
    verifyUserEmail,
    loginUser,
    logoutUser,
    readUser,
    updateProfile,
    sendResetPasswordLink,
    forgotPassword,
    resetPassword,
    // uploadAvatar,
    updateAvatar

}