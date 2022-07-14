const User = require('../src/models/user')
const jwt = require('jsonwebtoken')

async function encryptUserModel(data) {
    const userData = await new User(data)
    userData.encryptFieldsSync({ __secret__: process.env.DATABASE_ACCESS_KEY })
    return userData
}

module.exports = {
    encryptUserModel
}