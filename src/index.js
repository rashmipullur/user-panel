const express = require('express')
require('dotenv').config()
require('./db/mongoose')
const passport = require('passport')
const cors = require('cors')
const User = require('./models/user')
const Task = require('./models/task')
const userRouter = require('./routers/user')
const taskRouter = require('./routers/task')

// cors: (Cross Origin Resource Sharing) will add a header to the URL and allow an 
// external url to correctly read the information on the URL called. 
// This is one of the objectives of creating a rest API.

const app = express()
app.use(cors())
app.use(express.json())
//passport config
app.use(passport.initialize())
require('../config/passport')
const port = process.env.PORT


app.use(userRouter)
app.use(taskRouter)


app.listen(port, () => {
    console.log('Server is up on a port ' + port)
})