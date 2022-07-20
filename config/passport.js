const JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;
const opts = {}
const User = require('../src/models/user')
const passport = require('passport')

opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET;

passport.use(new JwtStrategy(opts, function (jwt_payload, done) {
    console.log("hello")
    console.log('payload received: ', jwt_payload);
    User.findOne({ _id: jwt_payload.id }, function (err, user) {
        if (err) {
            return done(err, false);
        }
        if (user) {
            console.log(user)
            const userData = { user, sessionId: jwt_payload.sessionId }
            return done(null, userData);
        } else {
            return done(null, false);
        }
    });
}));