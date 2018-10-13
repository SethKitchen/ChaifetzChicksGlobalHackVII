'use strict';
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
var FacebookStrategy = require('passport-facebook').Strategy;
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var sql = require('tedious').Connection;
var Request = require('tedious').Request;
var ConnectionPool = require('tedious-connection-pool');
var TYPES = require('tedious').TYPES;
var forceSsl = require('express-force-ssl');
var GOOGLE_CLIENT_ID = "250633503423-iunr9hrp9cbmppcqfc8e0p8bbc34d6uk.apps.googleusercontent.com";
var GOOGLE_CLIENT_SECRET = "cqjAY41SnLE9twUiJytKhkvC";
var FACEBOOK_CLIENT_ID = "319080175568896";
var FACEBOOK_CLIENT_SECRET = "504e0155253203b253e6f2d95ee129b7"; 
var MemoryStore = session.MemoryStore;
var sessionStore = new MemoryStore();

process.on('uncaughtException', function (err) {
    console.error(err);
    console.log("Node NOT Exiting...");
});

var options = {
    key: fs.readFileSync('server.key'),     // privkey.pem
    cert: fs.readFileSync('server.crt')   // cert.pem
};

var dbConfig = {
    server: "globalhack.database.windows.net", //tbd
    userName: 'sjkyv5', //tbd
    password: 'Happybirthday123', //tbd
    // When you connect to Azure SQL Database, you need these next options.  
    options: { encrypt: true, database: 'GlobalHack', rowCollectionOnDone: true }
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
    //Switch these depending on release version--
    callbackURL: "https://mygrate.herokuapp.com/signin-google",
    //callbackURL: "https://localhost/signin-google",
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
            InsertOrUpdateUserInDatabase(profile.id, profile.name.familyName, profile.name.givenName, profile.email, picture, request.session.id, function () {
                return done(null, profile);
            });
        });
    }
));

//   Use the FacebookStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Facebook
//   profile), and invoke a callback with a user object.
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_CLIENT_ID,
    clientSecret: FACEBOOK_CLIENT_SECRET,
    //NOTE :
    //Carefull ! and avoid usage of Private IP, otherwise you will get the device_id device_name issue for Private IP during authentication
    //The workaround is to set up thru the facebook cloud console a fully qualified domain name such as http://mydomain:3000/ 
    //then edit your /etc/hosts local file to point on your private IP. 
    //Also both sign-in button + callbackURL has to be share the same url, otherwise two cookies will be created and lead to lost your session
    //if you use it.
    //Switch these depending on release version--
    callbackURL: "https://mygrate.herokuapp.com/signin-facebook",
    //callbackURL: "https://localhost/signin-facebook",
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
            console.log(profile);
            if (profile.photos.length > 0) {
                picture = profile.photos[0].value;
            }
            InsertOrUpdateUserInDatabase(profile.id, profile.name.familyName, profile.name.givenName, profile.email, picture, request.session.id, function () {
                return done(null, profile);
            });
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

// GET /auth/facebook
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Google authentication will involve
//   redirecting the user to facebook.com.  After authorization, Facebook
//   will redirect the user back to this application at
app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: ['default', 'email'] })
);
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

app.get('/signin-facebook',
    passport.authenticate('facebook', {
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

app.get('/login', function (req, res) {
    res.render('login', { title: 'Chicks', user: req.user });
});

app.get('/tabs', ensureAuthenticated, function (req, res) {
    res.render('tabs', { title: 'Chicks', user: req.user });
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});


// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function (err, req, res, next) {
        res.status(err.status || 500);
        res.json({
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.json({
        message: err.message,
        error: {}
    });
});



// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
    if (req.user) { return next(); }
    res.redirect('/login');
}


function InsertOrUpdateUserInDatabase(userId, famName, giveName, email, picture, lastSessionId, callback) {
    //acquire a connection
    pool.acquire(function (err1, connection) {
        if (err1) {
            console.log(err1);
            callback(err1, false);
        }

        var request = new Request("IF EXISTS (SELECT * FROM Users WHERE UserId=@UserId) UPDATE Users SET FamilyName=@FamilyName, GivenName=@GivenName, Email=@Email, Picture=@Picture, LastSessionId=@LastSessionId WHERE UserId=@UserId ELSE INSERT INTO Users (UserId, FamilyName, GivenName, Email, Picture, LastSessionId) VALUES(@UserId,@FamilyName,@GivenName,@Email,@Picture,@LastSessionId)", function (err) {
            if (err) {
                console.log(err);
                connection.release();
                callback(err, false);
            }
            else {
                console.log("success");
                connection.release();
                callback(err, true);
            }
        });
        request.addParameter('UserId', TYPES.NChar, userId);
        request.addParameter('FamilyName', TYPES.NChar, famName);
        request.addParameter('GivenName', TYPES.NChar, giveName);
        request.addParameter('Email', TYPES.NChar, email);
        request.addParameter('Picture', TYPES.NChar, picture);
        request.addParameter('LastSessionId', TYPES.NChar, lastSessionId);
        connection.execSql(request);
    });
}

module.exports = app;
https.createServer(options, app).listen(443);
http.createServer(app).listen(process.env.PORT || 80);