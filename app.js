//jshint esversion:6

// ----------------------  Init Server ----------------------------
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const { log } = require("console");
const mongoose = require("mongoose");
// mongoose encryption
// const encrypt = require("mongoose-encryption"); 
// Hash 
// const md5 = require("md5");
// // bcrypt
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate'); 

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'our little secret.',
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// ----------------------  Mongoose & Passport Setup    ----------------------------
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// Using encryption 
// userSchema.plugin(encrypt,{secret: process.env.SECRET , encryptedFields :["password"]}); 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); 

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:  process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_ID,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// ----------------------  Routes ----------------------------

// Home Requests
app.get("/", function (req, res) {
    res.render("home");
});

// Google route
app.get("/auth/google", function(req,res){
    passport.authenticate("google", { scope: ["profile"] });
});


app.get('/auth/google/secrets', 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });



// Register Requests 
app.get("/register", function (req, res) {
    res.render("register");
});

app.post("/register", function(req, res){
    User.register(new User({username: req.body.username}), req.body.password, function(err, user){
        if(err){
            console.log(err);
            return res.render("register");
        }
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    });
});



// Login Requests 
app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login", function (req, res) {
    const user = new User ({
        username: req.body.username,
        password: req.body.password
    }); 
    req.login(user, function(err){
        if ( err ){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});


// Secrets route 
app.get("/secrets", function(req, res){
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        } else { 
            if (foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers}); 
            }
        }
    });
});

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else {
        res.redirect("/login"); 
    }
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret ; 
    
    User.findById(req.user.id, function(err,foundUser){
        if (err){
            console.log(err);
        }else {
            if (foundUser){
                foundUser.secret = submittedSecret; 
                foundUser.save(function(){
                    res.redirect("/secrets"); 
                }); 
            }
        }
    });
}); 


// logout route 
app.get("/logout", function(req,res){
    req.logout(function(err){
        if(err){
            console.log(err);
        }
    });
    res.redirect("/"); 
});



// App Listen to port 3000 
app.listen(3000, function () {
    console.log("Server Started on port 3000 ... ");
}); 