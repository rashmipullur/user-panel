const express = require('express')
const router = express.Router()
const adminControllers = require('../controllers/admin.controller')
const { authAdmin }  = require('../middleware/auth')
const { validate } = require('../validator/express.validator')
const { validateReq } = require('../../public/utils')

router.post('/admin/login', validate('loginUser'), validateReq, adminControllers.adminLogin)
router.post('/admin/logout', authAdmin, adminControllers.logout)
router.get('/admin/profile', authAdmin, adminControllers.adminProfile)

router.get('/admin/viewusers', authAdmin, adminControllers.viewUsers)
router.get('/admin/viewuser/:id', authAdmin, adminControllers.viewUser)
router.post('/admin/activeDeactiveUser/:id', authAdmin, adminControllers.activeDeactiveUser)
router.get('/admin/viewusertask/:id', authAdmin, adminControllers.viewUserTask)

router.post('/admin/searchtask/', authAdmin, adminControllers.searchTask)
module.exports = router

