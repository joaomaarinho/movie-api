const User = require('../models/User')
const validation = require('../helpers/validation')
const bcrypt = require('bcrypt')
const { v4: uuidv4 } = require('uuid')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const moment = require('moment')

const login = async (req, res) => {
  try {
    const { error } = validation.loginSchema.validate(req.body)

    if (error) {
      res.status(400).json({
        error: {
          status: 400,
          message: 'INPUT_ERRORS',
          errors: error.details,
          original: error._original,
        },
      })
    } else {
      const user = await User.findOne({ email: req.body.email })

      if (user) {
        const validatePassword = await bcrypt.compare(
          req.body.password,
          user.password,
        )

        if (validatePassword) {
          const accessToken = jwt.sign(
            { _id: user.id, email: user.email },
            process.env.SECRET_ACCESS_TOKEN,
            {
              expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
            },
          )

          const refreshToken = jwt.sign(
            { _id: user.id, email: user.email },
            process.env.SECRET_REFRESH_TOKEN,
            {
              expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
            },
          )

          if (await addRefreshToken(user, refreshToken)) {
            res.status(200).json({
              success: {
                status: 200,
                message: 'LOGIN_SUCCESS',
                accessToken,
                refreshToken,
              },
            })
          } else {
            res
              .status(500)
              .json({ error: { status: 500, message: 'SERVER_ERROR' } })
          }
        } else {
          res.status(403).json({
            error: { status: 403, message: 'INVALID_PASSWORD_OR_EMAIL' },
          })
        }
      } else {
        res
          .status(403)
          .json({ error: { status: 403, message: 'INVALID_USER_OR_PASSWORD' } })
      }
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
    console.log(error)
  }
}

const register = async (req, res, next) => {
  const { email, password } = req.body
  try {
    const { error } = validation.registerSchema.validate(req.body, {
      abortEarly: false,
    })

    if (error) {
      res.status(400).json({
        error: {
          status: 400,
          message: 'INPUT_ERRORS',
          errors: error.details,
          original: error._original,
        },
      })
    } else {
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(password, salt)

      const user = new User({
        email: email,
        password: hashedPassword,
        emailConfirmed: false,
        emailToken: uuidv4(),
        security: {
          tokens: [],
          passwordReset: {
            token: null,
            provisionalPassword: null,
            expiry: null,
          },
        },
      })

      await user.save()

      const accessToken = jwt.sign(
        { _id: user.id, email: user.email },
        process.env.SECRET_ACCESS_TOKEN,
        {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        },
      )

      const refreshToken = jwt.sign(
        { _id: user.id, email: user.email },
        process.env.SECRET_REFRESH_TOKEN,
        {
          expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        },
      )

      await User.updateOne(
        { email: user.email },
        {
          $push: {
            'security.tokens': {
              refreshToken: refreshToken,
              createdAt: new Date(),
            },
          },
        },
      )

      await sendEmailConfirmation({
        email: user.email,
        emailToken: user.emailToken,
      })

      res
        .status(200)
        .header()
        .json({
          success: {
            status: 200,
            message: 'REGISTER_SUCCESS',
            accessToken: accessToken,
            refreshToken: refreshToken,
            user: {
              id: user.id,
              email: user.email,
            },
          },
        })
    }
  } catch (err) {
    console.log(err)
    let errorMessage

    if (err.keyPattern.email === 1) {
      errorMessage = 'EMAIL_EXISTS'
    } else {
      errorMessage = err
    }

    res.status(400).json({ error: { status: 400, message: errorMessage } })
  }
}

const token = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken

    try {
      const decodedRefreshToiken = jwt.verify(
        refreshToken,
        process.env.SECRET_REFRESH_TOKEN,
      )
      const user = await User.findOne({ email: decodedRefreshToiken.email })
      const existingRefreshTokens = user.security.tokens

      if (
        existingRefreshTokens.some(
          (token) => token.refreshToken === refreshToken,
        )
      ) {
        const accessToken = jwt.sign(
          { _id: user.id, email: user.email },
          process.env.SECRET_ACCESS_TOKEN,
          {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
          },
        )

        res.status(200).json({
          success: {
            status: 200,
            message: 'ACCESS_TOKEN_GENERATED',
            accessToken: accessToken,
          },
        })
      } else {
        res
          .status(401)
          .json({ error: { status: 401, message: 'INVALID_REFRESH_TOKEN' } })
      }
    } catch (error) {
      res
        .status(401)
        .json({ error: { status: 401, message: 'INVALID_REFRESH_TOKEN' } })
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const resetPasswordConfirm = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email })

    if (user.security.passwordReset.token === req.body.passwordResetToken) {
      if (
        new Date().getTime() <=
        new Date(user.security.passwordReset.expiry).getTime()
      ) {
        await User.updateOne(
          { email: req.body.email },
          {
            $set: {
              password: user.security.passwordReset.provisionalPassword,
              'security.passwordReset.token': null,
              'security.passwordReset.provisionalPassword': null,
              'security.passwordReset.expiry': null,
            },
          },
        )
        res.status(200).json({
          success: { status: 200, message: 'PASSAWORD_RESET_SUCCESS' },
        })
      } else {
        await User.updateOne(
          { email: req.body.email },
          {
            $set: {
              'security.passwordReset.token': null,
              'security.passwordReset.provisionalPassword': null,
              'security.passwordReset.expiry': null,
            },
          },
        )
        res.status(401).json({
          error: { status: 401, message: 'PASSWORD_RESET_TOKEN_EXPIRED' },
        })
      }
    } else {
      res.status(401).json({
        error: { status: 401, message: 'INVALID_PASSWORD_RESET_TOKEN' },
      })
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const resetPassword = async (req, res) => {
  try {
    if (
      req.body.provisionalPassword.length >= 6 &&
      req.body.provisionalPassword.length <= 255
    ) {
      const salt = await bcrypt.genSalt(10)
      const hashedPassword = await bcrypt.hash(
        req.body.provisionalPassword,
        salt,
      )

      const passwordResetToken = uuidv4()
      const expiresIn = moment().add(10, 'm').toISOString()

      const user = await User.findOneAndUpdate(
        { email: req.body.email },
        {
          $set: {
            'security.passwordReset': {
              token: passwordResetToken,
              provisionalPassword: hashedPassword,
              expiry: expiresIn,
            },
          },
        },
      )

      await sendPasswordResetConfirmation({
        email: req.body.email,
        passwordResetToken: passwordResetToken,
      })
      {
        res.status(200).json({
          success: { status: 200, message: 'PASSWORD_RESET_EMAIL_SENT' },
        })
      }
    } else {
      res
        .status(400)
        .json({ error: { status: 400, message: 'PASSWORD_INPUT_ERROR' } })
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const changeEmail = async (req, res) => {
  try {
    if (validation.emailSchema.validate({ email: req.body.provisionalEmail })) {
      const accessToken = req.header('Authorization').split(' ')[1]
      const decodedAccessToken = jwt.verify(
        accessToken,
        process.env.SECRET_ACCESS_TOKEN,
      )

      const emailExists = await User.findOne({
        email: req.body.provisionalEmail,
      })

      if (!emailExists) {
        const changeEmailToken = uuidv4()
        const expiresIn = moment().add(10, 'm').toISOString()

        const user = await User.findOneAndUpdate(
          { email: decodedAccessToken.email },
          {
            $set: {
              'security.changeEmail': {
                token: changeEmailToken,
                provisionalEmail: req.body.provisionalEmail,
                expiry: expiresIn,
              },
            },
          },
        )

        await changeEmailConfirmation({
          email: user.email,
          emailToken: changeEmailToken,
        })

        res
          .status(200)
          .json({ success: { status: 200, message: 'CHANGE_EMAIL_SUCCESS' } })
      } else {
        res
          .status(400)
          .json({ error: { status: 400, message: 'EMAIL_ALREADY_REGISTERED' } })
      }
    } else {
      res
        .status(400)
        .json({ error: { status: 400, message: 'EMAIL_INPUT_ERROR' } })
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const changeEmailConfirm = async (req, res) => {
  try {
    const accessToken = req.header('Authorization').split(' ')[1]
    const decodedAccessToken = jwt.verify(
      accessToken,
      process.env.SECRET_ACCESS_TOKEN,
    )

    const user = await User.findOne({ email: decodedAccessToken.email })

    const emailExists = await User.findOne({
      email: user.security.changeEmail.provisionalEmail,
    })

    if (!emailExists) {
      if (user.security.changeEmail.token === req.body.changeEmailToken) {
        if (
          new Date().getTime() <=
          new Date(user.security.changeEmail.expiry).getTime()
        ) {
          await User.updateOne(
            { email: decodedAccessToken.email },
            {
              $set: {
                email: user.security.changeEmail.provisionalEmail,
                'security.changeEmail.token': null,
                'security.changeEmail.provisionalEmail': null,
                'security.changeEmail.expiry': null,
              },
            },
          )
          res
            .status(200)
            .json({ success: { status: 200, message: 'CHANGE_EMAIL_SUCCESS' } })
        } else {
          res.status(401).json({
            error: { status: 401, message: 'CHANGE_EMAIL_TOKEN_EXPIRED' },
          })
        }
      } else {
        res.status(401).json({
          error: { status: 401, message: 'INVALID_CHANGE_EMAIL_TOKEN' },
        })
      }
    } else {
      await User.updateOne(
        { email: decodedAccessToken.email },
        {
          $set: {
            email: user.security.changeEmail.provisionalEmail,
            'security.changeEmail.token': null,
            'security.changeEmail.provisionalEmail': null,
            'security.changeEmail.expiry': null,
          },
        },
      )
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const test = async (req, res, next) => {
  try {
    const newUser = await new User({
      email: 'test2@test.com',
      password: 'test',
      emailConfirmed: false,
      emailToken: 'test',
      security: {
        tokens: null,
        passwordReset: null,
      },
    })

    await newUser.save()
    res.send(newUser)
  } catch (error) {
    res.send(error)
  }
}

const addRefreshToken = async (user, refreshToken) => {
  try {
    const existingRefreshTokens = user.security.tokens

    if (existingRefreshTokens.length < 25) {
      await User.updateOne(
        { email: user.email },
        {
          $push: {
            'security.tokens': {
              refreshToken: refreshToken,
              createdAt: new Date(),
            },
          },
        },
      )
    } else {
      await User.updateOne(
        { email: user.email },
        {
          $pull: {
            'security.tokens': {
              _id: existingRefreshTokens[0]._id,
            },
          },
        },
      )

      await User.updateOne(
        { email: user.email },
        {
          $push: {
            'security.tokens': {
              refreshToken: refreshToken,
              createdAt: new Date(),
            },
          },
        },
      )
    }
    return true
  } catch (error) {
    return false
  }
}

const sendEmailConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  })

  const info = await transport.sendMail({
    from: '"Course test" <noreply@coursetest.com>',
    to: user.email,
    subject: 'Confirm your email!',
    text: `Click the link to confirm your email: http://localhost:9000/confirm-email/${user.emailToken}`,
  })
}

const sendPasswordResetConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  })

  const info = await transport.sendMail({
    from: '"Course test" <noreply@coursetest.com>',
    to: user.email,
    subject: 'Reset your password!',
    text: `Click the link to confirm your password reset: http://localhost:9000/confirm-password/${user.passwordResetToken}`,
  })
}

const confirmEmailToken = async (req, res) => {
  try {
    const emailToken = req.body.emailToken

    if (emailToken !== null) {
      const accessToken = req.header('Authorization').split(' ')[1]

      const decodedAccessToken = jwt.verify(
        accessToken,
        process.env.SECRET_ACCESS_TOKEN,
      )

      const user = await User.findOne({ email: decodedAccessToken.email })

      if (!user.emailConfirmed) {
        if (emailToken === user.emailToken) {
          await User.updateOne({
            email: decodedAccessToken.email,
            $set: { emailConfirmed: true, emailToken: null },
          })

          res
            .status(200)
            .json({ success: { status: 200, message: 'EMAIL_CONFIRMED' } })
        } else {
          res
            .status(401)
            .json({ error: { status: 401, message: 'INVALID_EMAIL_TOKEN' } })
        }
      } else {
        res
          .status(401)
          .json({ error: { status: 401, message: 'EMAIL_ALREADY_CONFIRMED' } })
      }
    } else {
      res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
    }
  } catch (error) {
    res.status(400).json({ error: { status: 400, message: 'BAD_REQUEST' } })
  }
}

const changeEmailConfirmation = async (user) => {
  const transport = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  })

  const info = await transport.sendMail({
    from: '"Course test" <noreply@coursetest.com>',
    to: user.email,
    subject: 'Change your email!',
    text: `Click the link to change your email: http://localhost:9000/change-email/${user.emailToken}`,
  })
}

module.exports = {
  test,
  register,
  token,
  confirmEmailToken,
  login,
  resetPassword,
  resetPasswordConfirm,
  changeEmailConfirm,
  changeEmail,
}
