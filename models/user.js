var mongoose = require('mongoose');
var Schema = mongoose.Schema;

module.exports = mongoose.model('User', new Schema({ 
    name: String, 
    password: String,
    email: String,
    todo:[String],
    pending:Number,
    salt:String
}));