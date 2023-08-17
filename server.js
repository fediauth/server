const express = require('express');
const app = express();
require('dotenv').config();
const port = 3000 || process.env.PORT;
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const mongourl = process.env.MONGOURL;
const registeringAllowed = process.env.REGISTERINGALLOWED;
const registeringPassword = process.env.REGISTERINGPASSWORD;
mongoose.connect(mongourl, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error'));
db.once('open', () => console.log('connected to db'));
const userSchema = new mongoose.Schema({
    name: String,
    username: String,
    email: String,
    password: String,
    accountid: String,
    salt: String,
});
const tokenSchema = new mongoose.Schema({
    accountid: String,
    token: String,
});
const Token = mongoose.model('Token', tokenSchema);
const User = mongoose.model('User', userSchema);
app.use(express.json());
app.use(cors());
app.get('/', (req, res) => res.send(`Server running. Uptime: ${process.uptime()}`));
app.post('/getuser', (req, res) => {
    const { token } = req.body;
    Token.findOne({ token: token }).then((token) => {
        if (token) {
            if (Date.now() - token._id.getTimestamp() > 1800000) {
                Token.deleteOne({ token: token.token }).then(() => {
                    res.status(400).send('Invalid/expired token');
                });
                return;
            }
            User.findOne({ accountid: token.accountid }).then((user) => {
                Token.deleteOne({ token: token.token }).then(() => {
                    res.json({
                        name: user.name,
                        email: user.email,
                        accountid: user.accountid,
                    });
                });
            });
        }
        else {
            res.status(400).send('Invalid/expired token');
        }
    });
});
app.post('/login', (req, res) => {
    const { username, prehashedpassword } = req.body;
    User.findOne({ username: username }).then((user) => {
        const hashedPassword = crypto.pbkdf2Sync(prehashedpassword, user.salt, 1000, 64, 'sha512').toString('hex');
        if (hashedPassword === user.password) {
            const token = crypto.randomBytes(32).toString('hex');
            const newToken = new Token({
                accountid: user.accountid,
                token: token,
            });
            newToken.save().then(() => {
                res.json({
                    token: token,
                });
            });
        }
        else {
            res.status(400).send('Invalid password');
        }
    });
});
app.post('/register', (req, res) => {
    const { name, username, email, prehashedpassword, registeringpassword } = req.body;
    if (registeringAllowed === 'false') {
        res.status(400).send('Registering is not allowed');
        return;
    }
    if (registeringPassword !== "none") {
        if (registeringPassword !== registeringpassword) {
            res.status(400).send('Invalid registering password');
            return;
        }
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = crypto.pbkdf2Sync(prehashedpassword, salt, 1000, 64, 'sha512').toString('hex');
    const accountid = crypto.randomBytes(16).toString('hex');
    const newUser = new User({
        name: name,
        username: username,
        email: email,
        password: hashedPassword,
        accountid: accountid,
        salt: salt,
    });
    newUser.save().then(() => {
        res.json({
            name: name,
            email: email,
            accountid: accountid,
        });
    });
});
app.listen(port, () => console.log(`Server listening on port ${port}`));