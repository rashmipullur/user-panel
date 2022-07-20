const VALIDATE = require('../../constants/validation.constant')

module.exports.validate = function (method) {
    switch(method) {
        case 'registerUser': {
            return [
                VALIDATE.EMAIL,
                VALIDATE.PASSWORD,
                VALIDATE.NAME,
                VALIDATE.PHONENO
            ]
        }
        case 'loginUser': {
            return [
                VALIDATE.EMAIL,
                VALIDATE.PASSWORD
            ]
        }
        case 'sendForgotPasswordLink': {
            return [
                VALIDATE.EMAIL
            ]
        }
        case 'forgotPassword': {
            return [
                VALIDATE.PASSWORD,
                VALIDATE.CONFIRMPASSWORD
            ]
        }
        case 'resetPassword': {
            return [
                VALIDATE.CURRENTPASSWORD,
                VALIDATE.PASSWORD,
                VALIDATE.CONFIRMPASSWORD
            ]
        }

    }
}