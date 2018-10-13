﻿'use strict';
var express = require('express');
var app = express();
var http = require('http');
var https = require('https');
var fs = require('fs');
var moment = require('moment');
var passport = require('passport');
var util = require('util');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var GoogleStrategy = require('passport-google-oauth2').Strategy;
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var sql = require('tedious').Connection;
var Request = require('tedious').Request;
var ConnectionPool = require('tedious-connection-pool');
var TYPES = require('tedious').TYPES;
var forceSsl = require('express-force-ssl');
var GOOGLE_CLIENT_ID = ""; //tbd
var GOOGLE_CLIENT_SECRET = ""; //tbd
var MemoryStore = session.MemoryStore;
var sessionStore = new MemoryStore();

process.on('uncaughtException', function (err) {
    console.error(err);
    console.log("Node NOT Exiting...");
});

/var options = {
    key: fs.readFileSync(''),     // privkey.pem
    cert: fs.readFileSync('')   // cert.pem
};

var dbConfig = {
    server: "", //tbd
    userName: '', //tbd
    password: '', //tbd
    // When you connect to Azure SQL Database, you need these next options.  
    options: { encrypt: true, database: 'Globalhack', rowCollectionOnDone: true }
};

var poolConfig = {
    min: 2,
    max: 4,
    log: true
};

//create the pool
var pool = new ConnectionPool(poolConfig, dbConfig);

pool.on('error', function (err) {
    console.error(err);
});

app.set('trust proxy', 1);
app.use(forceSsl);

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Google profile is
//   serialized and deserialized.
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (obj, done) {
    done(null, obj);
});


// Use the GoogleStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Google
//   profile), and invoke a callback with a user object.
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    //NOTE :
    //Carefull ! and avoid usage of Private IP, otherwise you will get the device_id device_name issue for Private IP during authentication
    //The workaround is to set up thru the google cloud console a fully qualified domain name such as http://mydomain:3000/ 
    //then edit your /etc/hosts local file to point on your private IP. 
    //Also both sign-in button + callbackURL has to be share the same url, otherwise two cookies will be created and lead to lost your session
    //if you use it.
    callbackURL: "https://localhost/signin-google",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        // asynchronous verification, for effect...
        process.nextTick(function () {

            // To keep the example simple, the user's Google profile is returned to
            // represent the logged-in user.  In a typical application, you would want
            // to associate the Google account with a user record in your database,
            // and return that user instead.
            var picture = null;
            if (profile.photos.length > 0) {
                picture = profile.photos[0].value;
            }
            /*InsertOrUpdateUserInDatabase(profile.id, profile.name.familyName, profile.name.givenName, profile.email, picture, request.session.id, function () {

                return done(null, profile);
            }); */
        });
    }
));

function sessionCleanup() {
    sessionStore.all(function (err, sessions) {
        for (var i = 0; i < sessions.length; i++) {
            sessionStore.get(sessions[i], function () { });
        }
    });
}

setInterval(sessionCleanup, 1.728 * Math.pow(10 ^ 8));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
app.use(favicon(__dirname + '/public/logo2.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'i like socks',
    cookie: { secure: true },
    store: sessionStore,
    proxy: true,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

/*
app.use('/', routes);
app.use('/users', users);
*/

// GET /auth/google
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Google authentication will involve
//   redirecting the user to google.com.  After authorization, Google
//   will redirect the user back to this application at /auth/google/callback
app.get('/auth/google', passport.authenticate('google', {
    scope: [
        'https://www.googleapis.com/auth/plus.login',
        'https://www.googleapis.com/auth/plus.profile.emails.read']
}));

// GET /auth/google/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/signin-google',
    passport.authenticate('google', {
        successRedirect: '/',
        failureRedirect: '/login'
    }));

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

app.get('/', function (req, res) {
    res.render('index', { title: 'Chicks', user: req.user });
});

module.exports = app;
https.createServer(options, app).listen(443);
http.createServer(app).listen(process.env.PORT || 80);