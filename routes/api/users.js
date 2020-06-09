const express = require('express');
const router = express.Router();
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const config = require('config')

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

    const { name, email, password } = req.body;

    try {
        // see if user exists
        let user = await User.findOne({email});
        if (user) {
            return res.status(400).json({errors: [{msg: 'user already exist'}]})
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
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), {
            expiresIn: 3600
        }, (err, token) => {
            if (err) throw err;
            res.json({token})
        })

    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server Error')
    }
});

module.exports = router;
