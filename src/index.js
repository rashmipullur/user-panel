const express = require('express')
require('dotenv').config()
require('./db/mongoose')
const passport = require('passport')
const cors = require('cors')
const port = process.env.PORT

const userRouter = require('./routes/user')
const taskRouter = require('./routes/task')
const adminRouter = require('./routes/admin.route')

// cors: (Cross Origin Resource Sharing) will add a header to the URL and allow an 
// external url to correctly read the information on the URL called. 
// This is one of the objectives of creating a rest API.

const app = express()
app.use(cors())
app.use(express.json())
//passport config
app.use(passport.initialize())
require('../config/passport')
//render image from public directory
app.use(express.static('uploads'));
app.use('/', express.static('uploads'));


 app.use(userRouter)
 app.use(taskRouter)
app.use(adminRouter)

app.listen(port, () => {
    console.log('Server is up on a port ' + port)
})