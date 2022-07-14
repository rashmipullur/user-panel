const mongoose = require('mongoose')
const Schema = mongoose.Schema

const userSessionSchema = new Schema({
    userid: {
        type: mongoose.Schema.Types.ObjectId,
        required: [true, 'User id is required!'],
        ref: 'User'
    },
    isActive: {
        type: Boolean,
        required: [true, 'Session status is required!']
    },
    expAt: {
        type: Number,
        required: [true, 'Session expire time is required!']
    }
}, {
    timestamp: true
})

module.exports = mongoose.model('UserSession', userSessionSchema)