require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const app = express(); 
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const bcrypt = require("bcrypt");


app.use(session({ 
  secret: 'our little secret.',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/myDatabase");
const UserSchema=new mongoose.Schema({
  email:String,
  password:String, 
  googleId: String,
  secret:String
});
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));

const secret="Thisisourlittlesecret.";
//UserSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});

UserSchema.plugin(passportLocalMongoose,{
  usernameField: "email"
});

UserSchema.plugin(findOrCreate);
const User=new mongoose.model("User",UserSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
}
);

passport.deserializeUser( function(id, done) {
  User.findById(id)
    .then(user => done(null, user))
    .catch(err => done(err));
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id },   { username: profile.displayName }, function (err, user) {
    return cb(err, user);
  });
}
));


app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

/*app.post("/register", async function(req, res){
  //const hashedPassword = await bcrypt.hash(req.body.password, 10);
  
  try {
    const newUser = new User({
      email: req.body.username,
      password:req.body.password,
    });

    await newUser.save(); // ✅ No callback needed
    res.render("secrets");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error saving user.");
  }
});
*/ 

//The above code is not longer needed as we are using passport-local-mongoose
app.post("/register", function(req, res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/secrets", async function(req, res) {
  try {
    const foundUsers = await User.find({ secret: { $ne: null } });
    res.render("secrets", { usersWithSecrets: foundUsers });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error retrieving secrets.");
  }
});

/*app.post("/login", async function (req, res) {

  const username = req.body.username;
  const password = req.body.password;

  try {
    console.log("Login attempt for:", username);

    const foundUser = await User.findOne({ email: username });

    if (!foundUser) {
      console.log("User not found!");
      return res.status(404).send("User not found");
    }

    console.log("User found:", foundUser.email);

    // Check password using bcrypt
    // const isMatch = await bcrypt.compare(password, foundUser.password);

    if (foundUser.password === password) {
      console.log("Password match! Rendering secrets page...");
      res.render("secrets");
    } else {
      console.log("Incorrect password!");
      res.status(401).send("Incorrect password");
    }
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).send("Internal Server Error");
  }
});*/
app.post("/login", function(req, res){
  const user=new User({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
}
);

app.post("/submit", async function(req, res) {
  const submittedSecret = req.body.secret;

  try {
    let foundUser;

    if (req.user.googleId) {
      foundUser = await User.findOne({ googleId: req.user.googleId });
    } else {
      foundUser = await User.findById(req.user._id);
    }

    if (foundUser) {
      foundUser.secret = submittedSecret;
      await foundUser.save();
      res.redirect("/secrets");
    } else {
      res.status(404).send("User not found.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Something went wrong.");
  }
});


app.get("/logout", function(req, res){
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect("/");
  });
});
app.listen(3000, function(){
  console.log("Server started on port 3000");
});