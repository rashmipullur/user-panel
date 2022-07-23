var ObjectId = require('mongoose').Types.ObjectId
const User = require('../models/user')
const Task = require('../models/task')
const AdminSession = require('../models/adminSession.model')
const jwt = require('jsonwebtoken')
const HTTP = require('../../constants/responseCode.constant')
const { hashSync, compareSync } = require('bcryptjs')
const { encryptUserModel, createSessionAndJwtToken, formateUserData } = require('../../public/utils');

(async function defaultAdminsignup(req, res) {
    try {
        const adminData = { name: "admin", email: "admin@gmail.com", role:"admin" }
        const password = "admin123"
        const encData = await encryptUserModel(adminData)
        const existsAdmin = await User.findOne({email: encData.email, role: encData.role})
        if(existsAdmin) return

        const userData = await new User({ ...adminData, password: hashSync(password.trim(), 8), isVerified: true }).save()
        if (!userData) console.log("Unable to add default admin")
        return
    } catch(e) {
        console.log(e)
        return
    }
})()

const adminLogin = async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'All fields are required', data: {} })
    }
    const encData = await encryptUserModel({ email, password })
    try {
        const user = await User.findOne({ email: encData.email })
        if(!user) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Email is incorrect.', data: {} })
        }
        if(user.role != "admin") {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Invalid credentials.', data: {} })
        }
        if(user.active !== true) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.UNAUTHORIZED, 'message': 'Your Account is De-activated!', data: {} })
        }
        
        const adminSessionExists = await AdminSession.findOne({ adminid: user._id, isActive: true })
        if (adminSessionExists) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Admin is already logged in other device!', data: {} })
        }
        if (!compareSync(req.body.password, user.password)) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Password is incorrect.', data: {} })
        }

        const expAt = (new Date().getTime() / 1000) + 86400
        const adminSession = await new AdminSession({
            adminid: user._id,
            isActive: true,
            expAt: expAt.toFixed()
        }).save()

        if (!adminSession) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Unable to store admin session.', data: {} })
        }
        const payload = { email: user.email, id: user._id, sessionId: adminSession._id }

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1d" })

        return res.status(HTTP.SUCCESS).send({
            'status': true,
            'message': "Logged in successfully!",
            'code': HTTP.SUCCESS,
            'data': {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    avatar: user.avatar,
                },
                token: "Bearer " + token
            }
        })

    } catch(e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!" })
    }
}

const logout = async (req, res) => {
    try {
        if (req.user) {
            const adminData = await AdminSession.findOneAndUpdate({ _id: req.user.sessionId, adminid: req.user._id, isActive: true }, { isActive: false }, { new: true })
            if (!adminData) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'Admin session is invalid', data: {} })
            }
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'Admin logged out successfully', data: {} })
        } else {
            return res.status(HTTP.BAD_REQUEST).send({ "status": false, 'code': HTTP.BAD_REQUEST, "message": "Please authenticate", data: {} })
        }
    } catch (e) {
        console.log(e)
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const adminProfile = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.UNAUTHORIZED, 'message': 'Please authenticate yourself.', data: {} })
        }
        const user = await User.findById({ _id: req.user._id })

        if (!user) {
            return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.NOT_FOUND, "message": "User not found!", data: {} })
        }
        return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, "message": "User profile.", data: await formateUserData(user) })
    } catch (err) {
        console.log(err);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const viewUsers = async (req, res) => {
    try {
        let formatedUserData = []
        const encData = await encryptUserModel({ role: "user" })
        let userData = await User.find({ role: encData.role })
        if (userData.length === 0) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'No users found.', data: {} })
        }
        for (const data of userData) { formatedUserData.push(await formateUserData(data)) }
        if (formatedUserData.length === 0) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'No users found.', data: {} })
        }
        return res.status(HTTP.SUCCESS).send({ "status": true, 'code': HTTP.SUCCESS, "message": "Users details.", data: formatedUserData })
    } catch(e) {
        console.log(e);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const viewUser = async (req, res) => {
    try {
        const userData = await User.findById(req.params.id)
        if(!userData) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'User not found.', data: {} })
        }
        const formatedUserData = await formateUserData(userData)
        return res.status(HTTP.SUCCESS).send({ "status": true, 'code': HTTP.SUCCESS, "message": "Users details.", data: formatedUserData })
    } catch(e) {
        console.log(e);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const activeDeactiveUser = async (req, res) => {
    try {
        const userData = await User.findById(req.params.id)
        if(!userData) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_FOUND, 'message': 'User not found.', data: {} })
        }
        if(userData.active === true) {
            userData.active = false
            await userData.save()
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'User Blocked.', data: {} })
        }
        if(userData.active === false) {
            userData.active = true
            await userData.save()
            return res.status(HTTP.SUCCESS).send({ 'status': true, 'code': HTTP.SUCCESS, 'message': 'User Unblocked.', data: {} })
        }
    } catch(e) {
        console.log(e);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const viewUserTask = async (req, res) => {
    try {
        const taskData = await Task.find({ owner: req.params.id})
        if(!taskData) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_FOUND, 'message': 'User not found.', data: {} })
        }
        let formatedTaskData = []
        for (const data of taskData) { formatedTaskData.push(data) }
        if (formatedTaskData.length === 0) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'No tasks found.', data: {} })
        }
        return res.status(HTTP.SUCCESS).send({ "status": true, 'code': HTTP.SUCCESS, "message": "Users details.", data: formatedTaskData })
    } catch(e) {
        console.log(e);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

const searchTask = async (req, res) => {
    try {
                
        const {subject, description, name, email} = req.body
        if (!subject && !description && !name && !email) {
            return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_FOUND, 'message': 'No data to search!', data: {} })
        }
        if (subject === (Task.find({subject: subject})) && !description && !name && !email) {
            
        }

    } catch(e) {
        console.log(e);
        return res.status(HTTP.SUCCESS).send({ "status": false, 'code': HTTP.INTERNAL_SERVER_ERROR, "message": "Something went wrong!", data: {} })
    }
}

module.exports = {
    adminLogin,
    logout,
    adminProfile,

    viewUsers,
    viewUser,
    activeDeactiveUser,
    viewUserTask,

    searchTask
}