const mongoose = require('mongoose');
const Schema = mongoose.Schema;

//create user and schema - einfaches model
const radioSchema = new Schema({
    radioname: String,
    radiourl: String,
    nowplayingurl: String,
    radiocountry: String,
    radiolanguage: String,
    securecontent: [],
    comments: []
});


//im model wird die collection definiert
const Radio = mongoose.model('radio', radioSchema);

module.exports = Radio;