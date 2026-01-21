require("dotenv").config()

const express = require("express")
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const User = require("./User")

const app = express()

// MIDDLEWARE
app.use(cors())
app.use(bodyParser.json())
app.use(express.static("public"))

const SECRET = process.env.JWT_SECRET

// ============================
// SPLUNK CONNECTION SETUP
// ============================
const SPLUNK_URL = process.env.SPLUNK_URL
const SPLUNK_TOKEN = process.env.SPLUNK_TOKEN

async function sendToSplunk(logData) {
  // If no URL is set, don't try to send (prevents crashes)
  if (!SPLUNK_URL) return

  try {
    await fetch(SPLUNK_URL, {
      method: "POST",
      headers: {
        "Authorization": `Splunk ${SPLUNK_TOKEN}`,
        "Content-Type": "application/json"
      },
      // Splunk expects the data inside an "event" key
      body: JSON.stringify({ event: logData })
    })
  } catch (error) {
    console.error("Splunk Error:", error.message)
  }
}

// LOGGING MIDDLEWARE
app.use((req, res, next) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    method: req.method,
    url: req.url
  }

  // 1. Print to Render Console
  console.log(`[${logEntry.timestamp}] IP=${logEntry.ip} METHOD=${logEntry.method} URL=${logEntry.url}`)

  // 2. Send to Splunk
  sendToSplunk(logEntry)

  next()
})

// ============================
// MONGODB ATLAS CONNECTION
// ============================
const MONGO_URI = process.env.MONGO_URI

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB Atlas Connected Successfully"))
  .catch(err => console.log("MongoDB Connection Failed:", err.message))

// ============================
// AUTH MIDDLEWARE
// ============================
function auth(req, res, next) {
  try {
    const token = req.headers.authorization
    const decoded = jwt.verify(token, SECRET)
    req.userId = decoded.id
    next()
  } catch {
    console.log("AUTH FAILURE - Invalid Token Attempt")
    res.status(403).send("Invalid Token")
  }
}

// ============================
// ROUTES
// ============================

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const hashed = await bcrypt.hash(req.body.password, 10)

    const user = new User({
      email: req.body.email,
      password: hashed,
      contacts: []
    })

    await user.save()
    console.log("NEW USER CREATED:", req.body.email)
    res.send("User Created")
  } catch {
    res.status(500).send("Signup Failed")
  }
})

// LOGIN
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email })

  if (!user) {
    console.log("LOGIN FAIL - USER NOT FOUND:", req.body.email)
    return res.status(401).send("User not found")
  }

  const valid = await bcrypt.compare(req.body.password, user.password)
  if (!valid) {
    console.log("LOGIN FAIL - WRONG PASSWORD:", req.body.email)
    return res.status(401).send("Wrong password")
  }

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "1h" })
  console.log("LOGIN SUCCESS:", req.body.email)
  res.json({ token })
})

// ADD PERSON / NOTE
app.post("/addcontact", auth, async (req, res) => {
  const user = await User.findById(req.userId)

  user.contacts.push({
    name: req.body.name,
    note: req.body.note
  })

  await user.save()
  console.log("CONTACT ADDED FOR USER:", user.email)
  res.send("Saved")
})

// GET CONTACTS
app.get("/contacts", auth, async (req, res) => {
  const user = await User.findById(req.userId)
  res.json(user.contacts)
})

// ============================
// START SERVER
// ============================
// 4. USE ENV VARIABLE FOR PORT (REQUIRED FOR DEPLOYMENT)
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`)
})

