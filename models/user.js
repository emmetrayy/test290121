const mongoose = require('mongoose');
const Schema = mongoose.Schema;

//create user and schema - einfaches model
const userSchema = new Schema({
    username: String,
    email: String,
    password: String,
    mode: String,
    channel: {
        radioname: String,
        radiourl: String,
        nowplayingurl: String,
        radiocountry: String,
        radiolanguage: String
    },
    alternativechannel: {
        radioname: String,
        radiourl: String,
        nowplayingurl: String,
        radiocountry: String,
        radiolanguage: String
    },
    shmoo: [],
    // playlist: [],
    privateplaylist: [],
    privatefilenames: [],
    privateplaylistfullname: [],
    // privateplaylistcounter: Number
});


userSchema.methods.validPassword = function( password ) {
    return ( this.password === password );
};


//im model wird die collection definiert, in dem fall testusers
const User = mongoose.model('users', userSchema);

module.exports = User;