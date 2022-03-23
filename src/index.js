const express = require('express')
const app = express()
const port = process.env.PORT

app.use(express.json())

const mongoose = require('mongoose')
const authController = require('./controllers/auth')

const authRoutes = require('./routes/auth')

app.use('/', authRoutes)

app.get('/test', async (req, res) => {
  await authController.test(req, res)
})

mongoose
  .connect(process.env.DB_URL, {
    // useNewUtlParser: true,
    useUnifiedTopology: true,
    // useFindAndModify: false,
    // useCreateIndex: true,
  })
  .then(() => {
    app.listen(port, () => {
      console.log(`API running on http://localhost:${port}`)
    })
  })
  .catch((err) => {
    console.log(err)
  })

process.on('SIGNINT', () => {
  mongoose.connection.close(() => {
    console.log('Mongoose disconnected on app termination')
    process.exit(0)
  })
})
