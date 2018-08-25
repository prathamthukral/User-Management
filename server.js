// dependencies
var express = require("express")
var app = express()
var port = 3000;
var bodyParser = require('body-parser')
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(express.json());
app.use(express.urlencoded());
var mongoose = require("mongoose")
var crypto = require("crypto")
const hash = crypto.createHash('sha256')

var User = require('./models/user'); // get our mongoose model

var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};
function saltHashPassword(userpassword,salt) {
    if (salt==undefined){
        salt = genRandomString(16); /** Gives us salt of length 16 */
    }
    var passwordData = sha512(userpassword, salt);
    return passwordData
}

mongoose.Promise = global.Promise;
mongoose.connect("mongodb://localhost:8080/user-db")
db = mongoose.connection;

app.listen(port, () => {
    console.log("Server listening on port " + port)
});

// allows server to access all files in the public folder (css, images, etc.)
app.use(express.static(__dirname + '/public'));

module.exports = User


// SIGN UP
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/views/index.html")
});

app.get("/signup", (req, res) => {
    res.sendFile(__dirname + "/views/signup.html")
});

app.post('/adduser', (req, res)=> {
    var input = req.body;
    var salted = saltHashPassword(input.password);
    input.password = salted.passwordHash
    input.salt = salted.salt

    User.findOne({
        email: input.email
    }, function(err, user) {
        if (err) throw err;

        if (!user) {
            newUser = new User(input);
            newUser.pending = 0;
            newUser.save();
            res.redirect("/login")        
        } else {
            res.redirect("/signup?error=alreadyUser")
        }
    })
});


// LOGIN
app.get("/login", (req, res) => {
    res.sendFile(__dirname + "/views/login.html")    
});

app.post("/checkLogin", (req, res) => {
    var pw = req.body.password

    User.findOne({
        email: req.body.email
    }, function(err, user) {
        if (err) throw err;

        if (!user) {
            res.redirect("/login?error=noUser")
        } else {
            var salted = saltHashPassword(pw,user.salt);
            pw = salted.passwordHash
            // check if password matches
            if (user.password != pw) {
                res.redirect("/login?error=wrongLogin");
            } else {
                res.sendFile(__dirname+"/views/profile.html");
            }

        }
    })
});