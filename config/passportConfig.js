const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');

var User = mongoose.model('User');

passport.use(
    new localStrategy({ 
        usernameField: 'Email',
        passwordField: 'Password'
    },
     (username, password, done) => {
        User.findOne({ Email: username },
            (err, user) => {
                if (err)
                    return done(err);
                //unknown user
                else if (!user)
                    return done(null, false, { message: 'Email is not registered. '});
                // wrong password
                else if (!user.verifyPassword(password))
                    return done(null, false, { message: 'Wrong Password.'});
                // authentication succeeded
                else
                    return done(null, user);
            });
     })
);