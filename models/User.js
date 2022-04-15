const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    token:{
        type: String,
        default:""
    },
    admin:{
        type:Boolean,
        default:false,
    },
},{timestamps:true}
)

const User = mongoose.model("User", UserSchema)
module.exports = User