const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt= require('jsonwebtoken');
const cors = require('cors');

const app = express();

const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;

mongoose.connect(MONGO_URL);

const userSchema = new mongoose.Schema({
    name : String, 
    email: String, 
    password: String,
});

const noticeSchema = new mongoose.Schema({
    title: String,
    body: String,
    category: {type: String, enum: ["parking", "covid", "maintenance"]},
    date : {type: Date},
});

const authJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if( !token ) {
        res.status(403).json({message: "access denied"});
    } else{
        jwt.verify(token, process.env.JWTSECRET, (err, user) => {
            if(err) {
                res.status(403).json({message: "access denied"});
            } else {
                req.user = user;
                next();
            }
        })
    }
}


const User = mongoose.model('User', userSchema);
const Notice = mongoose.model('Notice', noticeSchema);

app.use(cors());
app.use(express.json());

app.post('/register', async (req, res) => {
    try{
        const hashP = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashP,
        });
        await user.save();
        res.status(200).json({message: "User registered successfully"});
    } catch(error) {
        res.status(500).json({message: "Error"});
    }
})

app.post('/login', async(req, res) => {
    try{
        const user = await User.findOne({email: req.body.email});
        if( !user || !(await bcrypt.compare(req.body.password, user.password)) ) {
            res.status(400).json({message: "User not found"});    
        } else {
            const token = jwt.sign({id: user._id, email: user.email}, process.env.JWTSECRET, {
                expiresIn: '1h',
            })
            res.status(200).json({token: token, name: user.name});
        }
    } 
    catch(error) {
        res.status(500).json({message: "Error"});
    }
})

app.get('/products', async(req, res) => {
    try{
        const filterData = req.query.category ? {category: req.query.category} : {};
        const notices = await Notice.find({...filterData});
        res.json(notices);
    } 
    catch(error) {
        res.status(500).json({message: "Error"});
    }
})


app.listen(PORT, () => {
    console.log("Server is running");
})