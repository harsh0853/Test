//jshint esversion:6
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-find-or-create");

const app=express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
   secret:"Our little secret.",
   resave:false,
   saveUninitialized:false 
}));

app.use(passport.initialize());
app.use(passport.session());




mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser:true});


const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:["password"]});

const User= new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOne({ googleId: profile.id }).then(function(user) {
        return cb(null, user);
    });
    User.create({ googleId: profile.id }).then(function(user) {
        return cb(null, user);
    });
  }
));

app.get("/", function(req,res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});


app.get("/secrets", (req,res)=>{
    if(req.isAuthenticated()){
        User.find({secret:{$ne :null}}).then((foundUser)=>{
            res.render("secrets", {usersWithSecrets: foundUser});
        });
    }
    else{
        res.redirect("/login");
    }
});

app.get("/logout", (req,res)=>{
    req.logout(req.user, err => {
        if(err) return next(err);
        res.redirect("/");
      });
});

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});


app.post("/submit", (req,res)=>{
    const submittedSecret=req.body.secret;

    User.findById(req.user.id).then((foundUser)=>{
        if(foundUser){
            foundUser.secret=submittedSecret;
            foundUser.save().then(()=>{
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/register", function(req,res){
    User.register({username:req.body.username}, req.body.password , (err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res , function(){
                res.redirect("/secrets");
            });
        }
    });
    
    
});

app.post("/login", (req, res)=>{
      
    const user=new User({
        username:req.body.username, 
        password:req.body.password
    });
    req.login(user,(err)=>{

        if(err)
        console.log(err);
        else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }

    });
    
});


app.listen(3000, function(){
    console.log("Server running at port 3000.");
});