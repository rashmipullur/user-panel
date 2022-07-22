const express = require('express')
const router = express.Router()
const adminControllers = require('../controllers/admin.controller')
const authAdmin  = require('../middleware/auth')
const { validate } = require('../validator/express.validator')
const { validateReq } = require('../../public/utils')

router.post('/admin/login', validate('loginUser'), validateReq, adminControllers.adminLogin)
router.post('/admin/logout', authAdmin, adminControllers.logout)

router.get('/admin/profile', authAdmin, adminControllers.adminProfile)

module.exports = router
