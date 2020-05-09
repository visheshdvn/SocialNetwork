const express = require('express');
const router = express.Router();
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const {check, validationResult} = require('express-validator')

const User = require('../../models/User')

// @route   POST api/users
// @desc    register user
// @access  Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please include a password with 6 or more characters').isLength({min: 6}),
], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()})
    }

    const { name, email, password} = req.body;

    try {
        // see if user exists
        let user = await User.findOne({email});
        if (user) {
            res.status(400).json({errors: [{msg: 'user already exist'}]})
        }

        // Get User gravatar
        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        })

        user = new User({
            name,
            email,
            avatar,
            password
        })

        const salt = await bcrypt.genSalt(10);
        // Encrypt password
        user.password = await bcrypt.hash(password, salt)

        await user.save();

        // return json web token
        res.send('User registered')

    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server Error')
    }
});

module.exports = router;
