//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const app = express();
 
//const bcrypt = require("bcrypt");
app.use(session({ 
  secret: 'our little secret.',
  resave: false,
  saveUninitialized: false
}));

mongoose.connect("mongodb://127.0.0.1:27017/myDatabase");
const UserSchema=new mongoose.Schema({
  email:String,
  password:String
});
const secret="Thisisourlittlesecret.";
UserSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});


const User=new mongoose.model("User",UserSchema);





app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.post("/register", async function(req, res){
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

app.post("/login", async function (req, res) {
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
});

app.listen(3000, function(){
  console.log("Server started on port 3000");
});