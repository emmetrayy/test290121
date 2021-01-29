const express = require('express')
const axios = require('axios');
const app = express()  
const cookieSession = require('cookie-session')  
const bodyParser = require('body-parser')
const passport = require('passport')
const mongoose = require('mongoose');
const configDB = require('./config/database.js');
mongoose.connect(configDB.url);

//check if connection has been established - hat keine spezielle funktion, nur die bestätigung dass alles passt
mongoose.connection.once('open', function(){
   console.log('connection has been made, now make fireworks....');
}).on('error', function(error){
    console.log('connection error:', error);
});


// getting the local authentication type
const LocalStrategy = require('passport-local').Strategy

const User = require('./models/user');
const Radio = require('./models/radio');
let thechannel;


app.use(bodyParser.json())

app.use(cookieSession({  
    name: 'mysession',
    keys: ['vueauthrandomkey'],
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))

app.use(passport.initialize());

app.use(passport.session());

app.get("/", (req, res, next) => {
  res.send('hallo')
})

//user authentifizierung/login/logout
app.post("/api/register", (req, res) => {
    console.log('register backend post route');
    let user = new User({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        mode: 'alternativeChannel',
        channel: {radioname: 'unselected',
            radiourl: 'unselected',
            nowplayingurl: 'unselected',
            radiocountry: 'unselected',
            radiolanguage: 'unselected'
        },
        alternativechannel: {radioname: 'unselected',
            radiourl: 'unselected',
            nowplayingurl: 'unselected',
            radiocountry: 'unselected',
            radiolanguage: 'unselected'
        },
        playlist: ['track1','track2'],
        privateplaylistcounter: 0
    });
    if (req.body.password == 'danke') {
        user.save();
        res.status(201).send(user);
        console.log(user);
    } else {
        console.log('nononononononono')
    }
    
});

app.post('/api/login', passport.authenticate('local-login', {
    successRedirect: '/api/user',
    failureRedirect: '/api/login',
    failureFlash: true
}));


app.get("/api/logout", function(req, res) {  
  req.logout();
  console.log("logged out")
  return res.send();
});

const authMiddleware = (req, res, next) => {  
  if (!req.isAuthenticated()) {
    res.status(401).send('You are not authenticated')
  } else {
    return next()
  }
}

app.get("/api/user", authMiddleware, (req, res) => {
    let iddd = req.session.passport.user
    User.findOne({ _id: iddd }, function (err, user) {
        res.send({ user: user })
        thechannel = user.channel.radioname;
    });
});

passport.use('local-login', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
},
function(req, username, password, done){
    process.nextTick(function(){
        User.findOne({ 'username': username}, function(err, user){
            if(err)
                return done(err);
            if(!user)
                return done(null, false);
            if(!user.validPassword(password)){
                return done(null, false);
            }
            return done(null, user);
        })
    })
}                                             
))

passport.serializeUser(function(user, done){
    done(null, user.id);
});
//macht den user wieder komplett
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

//user settings post routes
app.post('/api/modeselection', (req, res) => {
    console.log('inside post modeselection backend');
    let newmode = req.body.selectedMode
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        user.mode = newmode
        user.save();
    })
});

app.post('/api/channelselection', (req, res) => {
    console.log('inside post channelselection backend');
    let newchannel = req.body.selectedChannel
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        Radio.findOne({ radioname: newchannel}, function (err, channel) {
            user.channel.radioname = channel.radioname;
            user.channel.radiourl = channel.radiourl;
            user.channel.nowplayingurl = channel.nowplayingurl
            user.save();
        });
    })
});

app.post('/api/alternativechannelselection', (req, res) => {
    console.log('inside post alternativechannelselection backend');
    let newalternativechannel = req.body.selectedAlternativeChannel
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        Radio.findOne({ radioname: newalternativechannel}, function (err, channel) {
            user.alternativechannel.radioname = channel.radioname;
            user.alternativechannel.radiourl = channel.radiourl;
            user.alternativechannel.nowplayingurl = channel.nowplayingurl
            user.save();
        });
    })
});

//shmoo settings post routes (shmooen, entshmooen)
app.post('/api/lol', (req, res) => {
    console.log('inside post lol backend');
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        user.shmoo.push(req.body.currentSong);
        user.save();
    })
    res.send('ok')
});

app.post('/api/shmoo', (req, res) => {
    console.log('inside post shmoo backend');
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        var toBeRemovedFromShmoo = req.body.elementToBeRemovedFromShmoo
        var index = user.shmoo.indexOf(toBeRemovedFromShmoo);
        if (index > -1) {
          user.shmoo.splice(index, 1);
        }
        user.save();
    })
});

app.post('/api/emailchange', (req, res) => {
    console.log('inside post modeselection backend');
    let newemail = req.body.newEmail
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        user.email = newemail
        user.save();
    })
});

//playlist settings post routes (löschen, hinzufügen)
const fs = require('fs');
app.post('/api/deleteprivateplaylistitem', (req, res) => {
    console.log('inside post deleteprivateplaylistitem backend');
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        var deleteprivateplaylistitem = req.body.privatePlaylistItem
        console.log(deleteprivateplaylistitem)
        var index = user.privateplaylist.indexOf(deleteprivateplaylistitem);
        if (index > -1) {
          user.privateplaylist.splice(index, 1);
        }
        var i;
        var filefs;
        for (i = 0; i < user.privateplaylistfullname.length; i++) {
          var itemfullname = user.privateplaylistfullname[i]
          console.log(itemfullname)
          var itemcheck = itemfullname.slice(33)
          if (itemcheck === deleteprivateplaylistitem) {
              var filefs = itemfullname.slice(0, 32);
              var itemcheck2 = itemfullname.slice(0, 32)
              console.log(itemcheck2)
              var index2 = user.privatefilenames.indexOf(itemcheck2);
              if (index2 > -1) {
                user.privatefilenames.splice(index2, 1);
              }
              var index3 = user.privateplaylistfullname.indexOf(itemfullname);
              if (index3 > -1) {
                user.privateplaylistfullname.splice(index3, 1);
              }
          }
          console.log(itemcheck)
        } 
        user.save();
        const path = '../client/static/uploads/' + filefs
        try {
          fs.unlinkSync(path)
          console.log('file removed!!!!!!')
        } catch(err) {
          console.error(err)
        }
        res.send('file removed!!')
    })
});



//multer for fileupload
const multer = require('multer')

const fileFilter = function(req, file, cb) {
    const allowedTypes = ["audio/mpeg", "audio/mp3"];
    if (!allowedTypes.includes(file.mimetype)) {
        const error = new Error('wrong file type');
        error.code = 'LIMIT_FILE_TYPES';
        return cb(error, false);
    }
    
    cb(null, true);
}

const MAX_SIZE = 20000000;
const upload = multer({
    // dest: '../client/static/uploads/',
    dest: '/var/www/html/',
    fileFilter,
    limits: {
        fileSize: MAX_SIZE
    }
})

app.post('/api/fileupload', upload.single('file'), (req, res) => {
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        var newfile = req.file.originalname;
        var newfilename = req.file.filename;
        var fullname = req.file.filename + '_' + req.file.originalname;
        console.log(newfile)
        user.privateplaylist.push(newfile);
        user.privatefilenames.push(newfilename);
        user.privateplaylistfullname.push(fullname);
        user.save();
    })
    res.json({ file: req.file });
});

app.use(function(err, req, res, next) {
    if(err.code === 'LIMIT_FILE_TYPES') {
    res.status(422).json({ error: 'only mp3 allowed'});
    return;
    }
    if(err.code === 'LIMIT_FILE_SIZE') {
    res.status(422).json({ error: 'file is too big. Max size: 20MB.'});
    return;
    }
})

//get routes
app.get("/api/radiodata", (req,res) => {
    Radio.find(function (err, radiodata) {
        res.send({ radiodata: radiodata})
    })
});

app.get("/api/securecontent", (req, res) => {
    Radio.findOne({ radioname: '88.6'}, function (err, radio) {
        res.send({ secureContent: radio.securecontent })
    });
});

app.get("/api/getcomments", (req, res) => {
    let id = req.session.passport.user
    User.findOne({ _id: id }, function (err, user) {
        var findchannel = user.channel.radioname
        Radio.findOne({ radioname: findchannel}, function (err, radio) {
            res.send({ comments: radio.comments })
        });
    })
});

app.post('/api/postcomment', (req, res) => {
    console.log('inside post comment backend');
    var radiotofind = req.body.channelToComment
    let newcomment = req.body.userWhoComments + ' : ' + req.body.newComment
    Radio.findOne({ radioname: radiotofind }, function (err, radio) {
        radio.comments.push(newcomment)
        radio.save();
    })
});


//handle production
    //Static folder
    app.use(express.static(__dirname + '/dist/'));
    
    //Handle SPA
    app.get(/.*/, (req, res) => res.sendFile(__dirname + '/dist/index.html'));


app.listen(3000, '46.101.174.202');   
  console.log("App listening on port 3000 on 46.101.174.202");