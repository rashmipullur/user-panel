const nodemailer = require('nodemailer')

var transport = nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "e11d19bc3faffe",
      pass: "524f075ca3a596"
    }
  })

const sendWelcomeEmail = (email, name) => {
    transport.sendMail({
        from: 'rashmipullur1@gmail.com',
        to: email,
        subject: 'Welcome',
        text: `Hello, ${name}. Let me know how you get along with the app.` // template string
    }, function(err, info) {
        if (err) {
          console.log(err)
        } else {
          console.log(info);
        }
     })
}

const sendCancellationEmail = (email, name) => {
    transport.sendMail({
        from: 'rashmipullur1@gmail.com',
        to: email,
        subject: 'Sorry to see you go!',
        text: `Goodbye, ${name}. I hope to see you back sometime soon.` // template string
    }, function(err, info) {
        if (err) {
          console.log(err)
        } else {
          console.log(info);
        }
     })
}

const sendOTPEmail = (email, name) => {
  var otp = Math.random()
  otp = otp * 1000000
  otp = parseInt(otp)
  transport.sendMail({
    from: 'rashmipullur1@gmail.com',
    to: email,
    subject: 'Otp for registration is:',
    html: "<h3>OTP for account verification is </h3>" + "<h1 style='font-weight:bold;'>" + otp + "</h1>", // html body
    text: `hello, ${name}.` // template string
}, function(err, info) {
    if (err) {
      console.log(err)
    } else {
      console.log(info)
      return otp
    }
 })
}

const sendVerifyEmail = (user, link) => {
  transport.sendMail({
    from: 'rashmipullur1@gmail.com',
    to: user.email,
    subject: 'Verify Email',
    text: `Hello ${user.name}. please click the link to verify email, ${link}`
  }, function(err, info) {
    if (err) {
      console.log(err)
    } else {
      console.log(info)
    }
  })
}

const sendForgotPasswordLink = (toEmail, link) => {
  transport.sendMail({
    from: 'rashmipullur1@gmail.com',
    to: toEmail,
    subject: 'Reset Password',
    text: `Hello. please click the link to set Password, ${link}`
  }, function(err, info) {
    if (err) {
      console.log(err)
    } else {
      console.log(info)
    }
  })
}

module.exports = {
    sendWelcomeEmail,
    sendCancellationEmail,
    sendOTPEmail,
    sendVerifyEmail,
    sendForgotPasswordLink
}