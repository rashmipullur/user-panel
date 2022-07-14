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
        case 'updateUser': {
            return [
                VALIDATE.NAME,
                VALIDATE.PHONENO
            ]
        }
        case 'sendForgotPasswordLink': {
            return [
                VALIDATE.EMAIL
            ]
        }

    }
}