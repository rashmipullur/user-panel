const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const mongooseFieldEncryption = require("mongoose-field-encryption").fieldEncryption

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if(!validator.isEmail(value)) {
                throw new Error("Email is not valid!")
            }
        }
    }, 
    password: {
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if(value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain "password"!')
            }
        }
    },name: {
        type: String,
        required: true,
        trim: true
    },
    phoneNo: {
        type: String,
        validate: {
            validator: function(v) {
              return /^(\+91[\-\s]?)?[0]?(91)?[789]\d{9}$/.test(v);
            },
            message: props => `${props.v} is not a valid phone number!`
          },
        required: true
    },
    avatar: {
        type: Buffer
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
}, {
    timestamps: true
})

userSchema.plugin(mongooseFieldEncryption, { 
    fields: ["email", "name", "phoneNo"], 
    secret: "somesecretkey",
    saltGenerator: function (secret) {
      return "1234567890123456"; 
      // should ideally use the secret to return a string of length 16, 
      // default = `const defaultSaltGenerator = secret => crypto.randomBytes(16);`, 
      // see options for more details
    },
  });

userSchema.methods.generateAuthToken = async function () {
    const user = this
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET)

    user.tokens = user.tokens.concat({ token })
    await user.save()
    return token
}

// Hash the plain text password before saving
// userSchema.pre('save', async function (next) {
//     const user = this
//     if (user.isModified('password')) {
//         user.password = await bcrypt.hash(user.password, 8)
//     }
//     next()
// })

userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email })
    if (!user) {
        throw new Error('Unable to login')
    }
    
    const isMatch = await bcrypt.compare(password, user.password)
    if(!isMatch) {
        throw new Error('Unable to login')
    }
    return user
}

userSchema.methods.toJSON = function () {
    const user = this
    const userObject = user.toObject()

    delete userObject.password
    delete userObject.tokens
    delete userObject.__v
    delete userObject.createdAt
    delete userObject.updatedAt

    return userObject
}

const User = mongoose.model('User', userSchema)
module.exports = User