const express = require('express');
const bodyParser = require('body-parser');
const ejs =  require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.set('strictQuery', false);
mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const secretKey = 'thisismyvarylongencryptionkey';
userSchema.plugin(encrypt, {secret: secretKey, encryptedFields: ['password']});

const User = mongoose.model('User', userSchema);

app.get('/', (req,res)=>{
    res.render('home');
});

app.get('/login', (req,res)=>{
    res.render('login');
});

app.get('/register', (req,res)=>{
    res.render('register');
});

app.post('/register', (req,res)=>{
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    newUser.save((err)=>{
        if(!err){
            res.render('secrets');
        }else{
            res.send(err);
        }
    })

});

app.post('/login', (req, res)=>{
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, (err, docs)=>{
        if(err){
            res.send(err);
        }else{
            if(docs.password == password){
                res.render('secrets');
            }
        }
    })
})


app.listen(3000, ()=>{
    console.log("Server is listening on Port 3000");
})
