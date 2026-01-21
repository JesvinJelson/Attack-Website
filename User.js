const mongoose = require("mongoose")

const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  contacts: [
    {
      name: String,
      note: String
    }
  ]
})

module.exports = mongoose.model("User", UserSchema)
