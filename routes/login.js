//receive all login, logout, register request
const express = require('express')

const {
    registerView, 
    loginView,
    registerUser,
    loginUser,
    dashboardView
} = require('../controllers/LoginController')

const router = express.Router()

router.get('/register',registerView)
router.post('/register',registerUser)
router.get('/login',loginView)
router.post('/login',loginUser)

router.get('/dashboard',dashboardView)

module.exports = router