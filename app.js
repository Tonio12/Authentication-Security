require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs =  require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook')


const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public'))
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
  }));

  app.use(passport.initialize());
  app.use(passport.session());


mongoose.set('strictQuery', false);
mongoose.connect('mongodb://127.0.0.1/userDB');

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model('User', userSchema);

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
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req,res)=>{
    res.render('home');
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/google', 
passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/login', (req,res)=>{
    res.render('login');
});

app.get('/register', (req,res)=>{
    res.render('register');
});

app.get('/secrets', (req,res)=>{
    User.find({ 'secret': { $ne: null }}, (err, foundUsers)=>{
        if(!err){
            if(foundUsers){
                res.render('secrets', {"usersWithSecrets": foundUsers});
            }
        }
    })
});

app.get('/submit', (req,res)=>{
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('/login');
    }
});

app.post('/submit', (req, res)=>{
    const userSecret = req.body.secret;
    User.findById({_id: req.user.id}, (err, foundUser)=>{
        if(!err){
            if(foundUser){
                foundUser.secret = userSecret;
                foundUser.save(()=>{
                    res.redirect('/secrets');
                })
            }
        }
    });
});

app.get('/logout', function(req, res){
    req.logout(function(err) {
        if (err) { 
            console.log(err);
         }else{
            res.redirect('/');
         }
        
      });
});

app.post('/register', (req,res)=>{
    User.register({username: req.body.username, active: false}, req.body.password, function(err, user) {
        if (err) { 
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate('local')(req,res, function(){
                res.redirect('/secrets');
            })
        }
    });
});


app.post('/login', (req, res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate('local')(req,res, function(){
                res.redirect('/secrets');
            })
        }
    })
})


app.listen(3000, ()=>{
    console.log("Server is listening on Port 3000");
})
