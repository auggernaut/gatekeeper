var url = require('url'),
    http = require('http'),
    https = require('https'),
    fs = require('fs'),
    express = require('express'),
    app = express();
    qs = require('querystring'),
    Sendgrid = require("sendgrid-web"),
    crypto = require("crypto"),
    mime = require("mime"),
    shasum = crypto.createHash('sha1');


app.use(express.bodyParser());


// Load config defaults from JSON file.
// Environment variables override defaults.
function loadConfig() {
    var config = JSON.parse(fs.readFileSync(__dirname + '/config.json', 'utf-8'));
    for (var i in config) {
        config[i] = process.env[i.toUpperCase()] || config[i];
    }
    console.log('Configuration');
    console.log(config);
    return config;
}

var config = loadConfig();

function authGit(code, cb) {
    var data = qs.stringify({
        client_id: config.git_oauth_client_id,
        client_secret: config.git_oauth_client_secret,
        code: code
    });

    var reqOptions = {
        host: config.git_oauth_host,
        port: config.git_oauth_port,
        path: config.git_oauth_path,
        method: config.git_oauth_method,
        headers: { 'content-length': data.length }
    };

    var body = "";
    var req = https.request(reqOptions, function (res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            body += chunk;
        });
        res.on('end', function () {
            cb(null, qs.parse(body).access_token);
        });
    });

    req.write(data);
    req.end();
    req.on('error', function (e) {
        cb(e.message);
    });
}

function sendEmail(json, cb) {

    var sendgrid = new Sendgrid({
        user: config.sendgrid_username,
        key: config.sendgrid_key
    });

    sendgrid.send({
        to: json.to,
        from: json.from,
        subject: json.subject,
        html: json.message
    }, function (err) {
        if (err) {
            cb(err);
        } else {
            cb(null, "Success");
        }
    });
}

function createS3Creds(filename, cb) {
    var createS3Policy;
    var s3Signature;
    var s3Credentials;
    var s3PolicyBase64, _date, _s3Policy;
    var mimeType = mime.lookup(filename);

    _date = new Date();
    s3Policy = {
        "expiration": "" + (_date.getFullYear()) + "-" + (_date.getMonth() + 12) + "-" + (_date.getDate()) + "T" + (_date.getHours() + 1) + ":" + (_date.getMinutes()) + ":" + (_date.getSeconds()) + "Z",
        "conditions": [
            { "bucket": "pegg" },
            [ "starts-with", "$key", ""],
            { "acl": "public-read" },
            /*  { "success_action_redirect": "http://localhost:8888/#reply" }, */
            ["starts-with", "$Content-Type", mimeType],
            ["content-length-range", 0, 2147483648]
        ]
    };

    console.log("Secret: " + config.aws_secret_access_key);

    var bufPolicy = new Buffer(JSON.stringify(s3Policy)).toString('base64');

    s3Credentials = {
        s3PolicyBase64: bufPolicy,
        s3Signature: crypto.createHmac("sha1", config.aws_secret_access_key).update(bufPolicy).digest("base64"),
        s3Key: config.aws_access_key,
        /*    s3Redirect: "http://localhost:8888/#reply",*/
        s3Policy: s3Policy,
        s3Mime: mimeType,
        filename: filename
    }

    cb(s3Credentials);

}

/*Accepts a Javascript Date object as the parameter;
 outputs an RFC822-formatted datetime string. */
function getRFC822Date(oDate) {
    var aMonths = new Array("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    var aDays = new Array( "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
    var dtm = new String();

    dtm = aDays[oDate.getDay()] + ", ";
    dtm += padWithZero(oDate.getDate()) + " ";
    dtm += aMonths[oDate.getMonth()] + " ";
    dtm += oDate.getFullYear() + " ";
    dtm += padWithZero(oDate.getHours()) + ":";
    dtm += padWithZero(oDate.getMinutes()) + ":";
    dtm += padWithZero(oDate.getSeconds()) + " " ;
    dtm += getTZOString(oDate.getTimezoneOffset());
    return dtm;
}

//Pads numbers with a preceding 0 if the number is less than 10.
function padWithZero(val) {
    if (parseInt(val) < 10) {
        return "0" + val;
    }
    return val;
}

/* accepts the client’s time zone offset from GMT in minutes as a parameter.
 returns the timezone offset in the format [+|-}DDDD */
function getTZOString(timezoneOffset) {
    var hours = Math.floor(timezoneOffset / 60);
    var modMin = Math.abs(timezoneOffset % 60);
    var s = new String();
    s += (hours > 0) ? "-" : "+";
    var absHours = Math.abs(hours)
    s += (absHours < 10) ? "0" + absHours : absHours;
    s += ((modMin == 0) ? "00" : modMin );
    return(s);
}





// Convenience for allowing CORS on routes - GET only
app.all('*', function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});


app.get('/authgit/:code', function (req, res) {
    console.log('authenticating git code:' + req.params.code);
    authGit(req.params.code, function (err, token) {
        var result = err || !token ? { "error": "bad_code" } : { "token": token };
        console.log(result);
        res.json(result);
    });
});

app.post('/email', function (req, res) {
    console.log('sending email:' + JSON.stringify(req.body));
    sendEmail(req.body, function (err, token) {
        var result = err || !token ? { "error": err } : { "token": token };
        console.log(result);
        res.json(result);
    });
});


app.get('/s3policy/:filename', function (req, res) {
    console.log('get S3 Policy:' + req.params.filename);
    createS3Creds(req.params.filename, function (s3Credentials) {
        console.log(s3Credentials);
        res.json(s3Credentials);
    });
});


app.get('/blitlineSig', function (req, res) {
    console.log('get Blitline signature');
    var expiresTimePlusSecret = config.blitline_secret + getRFC822Date(new Date(2014, 11, 25));
    //TODO: expiration date should be minutes from now
    shasum.update(expiresTimePlusSecret);
    var signature = shasum.digest('hex');
    console.log(signature);
    res.json(signature);

});


var port = process.env.PORT || config.port || 9999;

app.listen(port, null, function (err) {
    console.log('Gatekeeper, at your service: http://localhost:' + port);
});
