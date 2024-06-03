
const express = require("express")
const router = express.Router()
const User = require("../models/User")
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const fetchUser = require("../middlewares/fetchUser.js")
const JWT_SECRET = "Amanisagoodbo$y"
const nodemailer = require("nodemailer")

// ROUTE 1: Create a User using:POST "/api/auth/createuser". No login required
router.post("/createuser", [body('email', "Enter a valid email").isEmail(), body('phone', "Enter a valid phone number").isLength({ min: 10, max: 10 }), body('name', "Enter a valid name").isLength({ min: 3 }), body('password', "Password must be atleast 5 characters").isLength({ min: 5 })
], async (req, res) => {
    let success = false;
    //If there are errors, return Bad request and the errors

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success, errors: errors.array() });
    }
    //Check weather the user with this email exists already
    try {
        let user = await User.findOne({ phone: req.body.phone })
        if (user) {
            return res.status(400).json({ success, error: "Sorry a user with this phone already exists" })
        }
        const salt = await bcrypt.genSalt(10);
        secPass = await bcrypt.hash(req.body.password, salt)
        user = await User.create({
            name: req.body.name,
            password: secPass,
            email: req.body.email,
            phone: req.body.phone,
            address: req.body.address
        })
        const data = {
            id: user.id
        }
        const authtoken = jwt.sign(data, JWT_SECRET)
        success = true
        res.json({ success, authtoken })
    }
    catch (error) {
        console.error(error.message)
        res.status(500).send("Internal server error")
    }
})

// ROUTE 2: Authenticate a User using:POST "/api/auth/login". Login required
router.post("/login", [body('email', "Enter a valid email").isEmail(), body('password', "Password cannot be blank").exists()
], async (req, res) => {
    //If there are errors, return Bad request and the errors
    let success = false
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password, phone } = req.body
    try {
        let user = await User.findOne({ email: email })
        if (!user) {
            success = false
            return res.status(400).json({ error: "Please try to login with correct credentials" })
        }
        const passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            success = false
            return res.status(400).json({ success, error: "Please try to login with correct credentials" })
        }
        const data = {
            id: user.id
        }
        const authtoken = jwt.sign(data, JWT_SECRET)
        success = true
        res.json({ success, authtoken })
    }
    catch (error) {
        console.error(error.message)
        res.status(500).send("Internal server error")
    }
})

// ROUTE 3: Authenticate a User using:POST "/api/auth/getUser". Login required
router.post('/getUser', fetchUser, async (req, res) => {
    try {
        const userId = req.user.id
        const user = await User.findById(userId).select("-password")
        res.json(user)
    } catch (error) {
        console.error(error.message)
        res.status(500).send("Internal server error")
    }
})

router.post('/forgotpassword', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "10m", });
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "211b414@juetguna.in",
                pass: "odll fbgn uskg rotb",
            },
        });
        const mailOptions = {
            from: process.env.EMAIL,
            to: req.body.email,
            subject: "Reset Password",
            html: `<h1>Reset Your Password</h1>
      <p>Click on the following link to reset your password:</p>
      <a href="http://localhost:5173/reset-password/${token}">http://localhost:5173/reset-password/${token}</a>
      <p>The link will expire in 10 minutes.</p>
      <p>If you didn't request a password reset, please ignore this email.</p>`,
        };
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.status(500).send({ message: err.message });
            }
            res.status(200).send({ message: "Email sent" });
        });
    }
    catch (err) {
        res.status(500).send({ message: err.message });
    }
})

router.post("/reset-password/:token", async (req, res) => {
    try {
        const decodedToken = jwt.verify(
            req.params.token,
            JWT_SECRET
        );
        if (!decodedToken) {
            return res.status(401).send({ message: "Invalid token" });
        }
        const user = await User.findOne({ _id: decodedToken.userId });
        if (!user) {
            return res.status(401).send({ message: "no user found" });
        }
        const salt = await bcrypt.genSalt(10);
        req.body.newPassword = await bcrypt.hash(req.body.newPassword, salt);
        user.password = req.body.newPassword;
        await user.save();
        res.status(200).send({ message: "Password updated" });
    }
    catch (err) {
        res.status(500).send({ message: err.message });
    }

})

module.exports = router
