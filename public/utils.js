const { validationResult } = require('express-validator')
const User = require('../src/models/user')
const UserSession = require('../src/models/userSession.model')
const jwt = require('jsonwebtoken')

function validateReq(req, res, next) {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        const errMsg = errors.errors.map(err => err.msg)
        if (errMsg && errMsg.length > 0) return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': errMsg[0], data: {} })
    } else {
        return next()
    }
}

async function encryptUserModel(data) {
    const userData = await new User(data)
    userData.encryptFieldsSync({ __secret__: process.env.DATABASE_ACCESS_KEY })
    return userData
}

async function createSessionAndJwtToken(user) {
    try {
        const expAt = (new Date().getTime() / 1000) + 86400
        const userSession = await new UserSession({ userid: user.id, isActive: true, expAt: toFixed() }).save()
        if (!userSession) {
            throw("Unable to store user session!")
        }

        const payload = { email: user.email, id: user._id, sessionId: userSession._id }
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' })
        return token
    } catch(e) {
        console.log(e)
        throw new Error("Unable to create session or JWT token")
    }
}

module.exports = {
    validateReq,
    encryptUserModel,
    createSessionAndJwtToken
}