const mongoose = require('mongoose');
const passport = require('passport');
const { json } = require('body-parser');
const _ = require('lodash');

const User = mongoose.model('User');

module.exports.register = (req, res, next) =>{
   var user = new User();
   user.Name = req.body.Name;
   user.Email = req.body.Email;
   user.Password = req.body.Password;
   
   user.save((err, doc) => {
    
       if (!err){
        
            res.send(doc);
       }
        else{
            
            if (err.code == 11000){
               
                res.status(422).send(['Email already registerd.']);
            }
            else{
               
                return next(err);
               

            }
                
        }
            
   });
};

module.exports.authenticate = (req, res, next) => {
    // call for passport authentication
    passport.authenticate('local', (err, user, info) => {
        // error from passport middleware
        if (err) return res.status(400).json(err);
        // registerd user
        else if (user) return res.status(200).json({ "token": user.generateJwt()});
        // unknown user or wrong password
        else return res.status(404).json(info)
    })(req, res);
}

module.exports.userProfile = (req, res, next) =>{
    
    User.findOne({ _id: req._id},
        (err, user) => {
            
            if (!user)
                return res.status(404).json({ status: false, message: 'User record not found.'});
            else
                return res.status(200).json({ status: true, user: _.pick(user, ['Name', 'Email'])});
        });
}