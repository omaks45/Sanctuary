const mongoose = require("mongoose")
const express = require("express")
const app = express()

const bodyParser = require("body-parser")
const cookieParser = require("cookie-parser")
const cors = require("cors")
require("dotenv").config();

const connectToDatabase = require('./config/db')

//Db connection
connectToDatabase();

// Use parsing middleware
 app.use(bodyParser.json())
 app.use(cookieParser())
 app.use(cors());

// Import the routes
const userRoutes = require("./route/user")

// Using routes
app.use('/api', userRoutes) 
 app.get('/health', (req, res) => {
   console.log('checking health')
     res.send('good ')
     })
     app.get('/', (req, res) => {
       console.log('checking home page')
         res.send('OK')
         })

const port = process.env.PORT

//Starting a server
app.listen(port, () => {
  console.log('App is running perfectly well')
})
