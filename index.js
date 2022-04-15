//main program
const express = require('express')
const app = express()
const PORT = 3100
const db = require('./db/db')
const passport = require('passport')
const session = require('express-session')
const { loginCheck } = require('./auth/passport')
loginCheck(passport)

const loginRouter = require('./routes/login')
const dashboardRouter = require('./routes/dashboard')


app.set('view engine','ejs')
app.use(express.urlencoded({extended: false}))

app.use(session({
    secret: 'api-niie',
    saveUnitialized: true,
    resave: true
}))

app.use(passport.initialize())
app.use(passport.session())

//Router

app.use('/',require('./routes/login'))
app.use('/',require('./routes/dashboard'))

app.listen(PORT,console.log('Server has started at port ' + PORT))