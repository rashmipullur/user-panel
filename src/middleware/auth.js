const jwt = require('jsonwebtoken')
const passport = require('passport')
const HTTP = require('../../constants/responseCode.constant')
var ObjectId = require('mongoose').Types.ObjectId
const UserSession = require('../models/userSession.model')
const User = require('../models/user')

// verify the authentication token
// const auth = async (req, res, next) => {
//     try {
//         const token = req.header('Authorization').replace('Bearer ','')
//         const decoded = jwt.verify(token, process.env.JWT_SECRET)
//         const user = await User.findOne({ _id: decoded._id, 'tokens.token': token })
//         if (!user) { throw new Error() }
//         req.token = token
//         req.user = user
//         next()
//     } catch(e) {
//         res.status(401).send({ error: 'Please authenticate.' , e})
//     }
// }


//user authorization
function authUser(req, res, next) {
    passport.authenticate('jwt', { session: false }, async function (err, userData, info, status) {
        try {
            if (err) {
                console.log(err)
                return next(err)
            }

            const { user, sessionId } = userData
            
            if (!user) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.UNAUTHORIZED, 'message': 'Please authenticate your-self', data: {} });
            }

            //if user blocked
            if (user && user.active === false) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_ALLOWED, 'message': 'Your Account is De-activated!', data: {} })
            }

            if (!sessionId || !ObjectId.isValid(sessionId)) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.NOT_ALLOWED, 'message': 'Invalid session!', data: {} })
            }

            const userSession = await UserSession.findOne({ _id: sessionId, userid: user._id, isActive: true })
            if (!userSession) {
                return res.status(HTTP.SUCCESS).send({ 'status': false, 'code': HTTP.BAD_REQUEST, 'message': 'User session is expired!', data: {} })
            }

            req.user = user
            req.user.sessionId = sessionId
            
            return next()
        } catch (e) {
            console.log("error from user middleware", e);
            return next()
        }
    })(req, res, next);
}

module.exports = authUser