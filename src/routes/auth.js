const express = require('express')
const authController = require('../controllers/auth')
const rateLimiter = require('../helpers/rateLimiter')
const verifyToken = require('../helpers/verifyToken')

const router = express.Router()

router.get('/test', [rateLimiter(1, 10), verifyToken], authController.test)

router.post('/login', authController.login)

router.post('/register', [rateLimiter(5, 5)], authController.register)

router.post('/token', authController.token)

router.post(
  '/confirm-email-token',
  [verifyToken],
  authController.confirmEmailToken,
)

router.post(
  '/reset-password',
  [rateLimiter(5, 5)],
  authController.resetPassword,
)

router.post(
  '/reset-password-confirm',
  [rateLimiter(5, 5)],
  authController.resetPasswordConfirm,
)

router.post(
  '/change-email',
  [rateLimiter(5, 5), verifyToken],
  authController.changeEmail,
)

router.post(
  '/change-email-confirm',
  [rateLimiter(5, 5), verifyToken],
  authController.changeEmailConfirm,
)

module.exports = router
