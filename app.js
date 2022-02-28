require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const url = require('url');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require("passport");
const cookieParser = require("cookie-parser");
const flash = require("connect-flash");
const mongoose = require("mongoose");
const nodemailer = require('nodemailer');
const randomBytes = require('randombytes');
const multer = require('multer');
const Jimp = require('jimp');
const fs = require('fs');
const localStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate');
const {
  get
} = require('http');

const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(cookieParser("secret"));
app.use(session({
  secret: process.env.SECRET,
  maxAge: 60 * 1000,
  resave: true,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

//mongoose
//mongodb://localhost:27017//userDB
//
mongoose.connect("mongodb+srv://shivam:Shivam0401@blog.jdkd4.mongodb.net/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true
});

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: String,
  googleId: String,
  bio: {
    type: String,
    default: ""
  },
  dark_theme: {
    type: Boolean,
    default: false
  },
  dp: {
    type: String,
    default: "default.svg"
  }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user", userSchema);

const postSchema = new mongoose.Schema({
  authorID: {
    type: String,
    required: true,
  },
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  like: {
    type: Array,
  },
  time: {
    type: String,
  }
});
const Post = new mongoose.model("post", postSchema);


/*const likeSchema = new mongoose.Schema({
  postID: {
    type: String,
    required: true,
  },
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  time: {
    type: String,
  }
});
const Like = new mongoose.model("likes", likeSchema);*/

const tokenSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    expires: '10m',
    default: Date.now
  }
});
const Token = new mongoose.model("token", tokenSchema);

//multer

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './public/uploads')
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname)
  }
});
const upload = multer({
  storage: storage
}).single('image');

//passport

passport.use(new localStrategy({
    usernameField: "email"
  },
  function (email, password, done) {
    User.findOne({
      email: email
    }, function (err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, {
          message: "User doesn't exist!"
        });
      }
      if (user && user.password == null) {
        return done(null, false, {
          message: "You have previously signed in using Google!! Login with Google to continue!"
        });
      }
      bcrypt.compare(password, user.password, function (err, result) {
        if (err) {
          return done(null, false);
        }
        if (!result) {
          return done(null, false, {
            message: "Incorrect Password!"
          });
        }
        if (result) {
          return done(null, user);
        }
      })
    });
  }));


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, {
      email: profile.emails[0].value,
      username: profile.displayName,
      password: null
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});
passport.deserializeUser(function (id, cb) {
  User.findById(id, function (err, user) {
    cb(err, user);
  });
});

//flash

app.use(function (req, res, next) {
  res.locals.success_message = req.flash("success_message");
  res.locals.error_message = req.flash("error_message");
  res.locals.error = req.flash("error");
  next();
});

//auth

const checkAuthenticated = function (req, res, next) {
  if (req.isAuthenticated()) {
    res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
    next();
  } else {
    req.flash('error_message', "Please Login to continue!");
    res.redirect('/login');
  }
}

//mailer

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL,
    pass: process.env.GPASS
  }
});

//adding username to array

var usersname = [];

setInterval(function () {
  usersname = [];
  User.find({}, function (err, authors) {
    if (err) throw err;
    authors.forEach(author => {
      if (author.email != "theblogpostbyshivam@gmail.com") {
        usersname.push(author.username);
      }
      if (!author.password && author.googleId == null) {
        User.deleteOne({
          _id: author._id
        }, function (err) {
          if (err) throw err;
        })
      }
    });
    usersname.sort();
  })
}, 10 * 60 * 1000);

//routes


app.get("/auth/google",
  passport.authenticate('google', {
    scope: ['profile', 'email']
  }));

app.get('/auth/google/setpassword',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    res.redirect('/profile');
  });

app.route("/register")
  .get(function (req, res) {
    res.render("logfiles/register")
  })

  .post(function (req, res) {
    var {
      username,
      email
    } = req.body;
    User.findOne({
      email: email
    }, function (err, user) {
      if (err) throw err;
      if (user) {
        res.render("logfiles/register", {
          error: "Email already Exists!"
        });
      }
      if (!user) {
        const newUser = new User({
          username: username,
          email: email,
          dark_theme: false,
          googleId: null
        });
        randomBytes(16, function (err, resp) {
          if (err) throw err;
          var token = resp.toString('hex');
          const newToken = new Token({
            email: req.body.email,
            token: token
          })
          const url = process.env.NURL + token;
          var mailOptions = {
            from: process.env.GMAIL,
            to: req.body.email,
            subject: 'Verification link to sign up!!',
            html: `<p> Click on this link to set your password : ${url} </p>`
          };
          transporter.sendMail(mailOptions, function (err, info) {
            if (err) throw err;
            newToken.save();
            usersname.push(username);
            newUser.save(function (err) {
              if (err) throw err;
              req.flash("success_message", "A verification link has been send to " + info.envelope.to[0] + ". Valid for 10 minutes.");
              res.redirect("/register");
            })
          });
        })
      }
    })
  });


app.route("/login")
  .get(function (req, res) {
    res.render("logfiles/login");
  })

  .post(function (req, res, next) {
    passport.authenticate('local', {
      failureRedirect: '/login',
      successRedirect: '/',
      failureFlash: true
    })(req, res, next)
  })

app.route("/forgotpassword")
  .get(function (req, res) {
    if (req.user) {
      res.redirect("/profile")
    } else {
      res.render("logfiles/forgotpassword");
    }
  })
  .post(function (req, res) {
    User.findOne({
      email: req.body.email
    }, function (err, user) {
      if (err) throw err;
      if (user) {
        randomBytes(16, function (err, resp) {
          var token = resp.toString('hex');
          const newToken = new Token({
            email: req.body.email,
            token: token
          })
          const url = process.env.NURL + token;
          var mailOptions = {
            from: process.env.GMAIL,
            to: req.body.email,
            subject: 'Verification link to change password!!',
            html: `<p> Click on this link to reset your password : ${url} </p>`
          };
          transporter.sendMail(mailOptions, function (err, info) {
            if (err) throw err;
            newToken.save();
            req.flash("success_message", "A verification link has been send to " + info.envelope.to[0] + ". Valid for 10 minutes.");
            res.redirect("/forgotpassword")
          });
        });
      } else {
        res.render('logfiles/forgotpassword', {
          error_message: "Email doesn't exist.."
        })
      }
    })
  })

app.route("/token/:passlink")
  .get(function (req, res) {
    Token.findOne({
      token: req.params.passlink
    }, function (err, usertoken) {
      if (err) throw err;
      if (!usertoken) {
        res.render("logfiles/setpassword", {
          error_message: "Link tempered or expired!",
          link: ""
        });
      }
      if (usertoken) {
        res.render("logfiles/setpassword", {
          success_message: "Set password  for account " + usertoken.email,
          link: usertoken.token
        });
      }
    })
  })
  .post(function (req, res) {
    Token.findOne({
      token: req.params.passlink
    }, function (err, usertoken) {
      if (err) throw err;
      if (!usertoken) {
        res.render("logfiles/setpassword", {
          error_message: "Link tempered or expired!",
          link: ""
        });
      }
      if (usertoken) {
        bcrypt.hash(req.body.password, saltRounds).then(function (hash) {
          User.updateOne({
            email: usertoken.email
          }, {
            password: hash
          }, function (err) {
            if (err) throw err;
            req.flash("success_message", "Password changed succesfully. Log in to continue!")
            res.redirect("/login");
          })
        })
      }
    })
  })





app.get("/", checkAuthenticated, function (req, res) {
  Post.find(function (err, posts) {
    if (err) throw err;
    res.render("posts/home", {
      dark: req.user.dark_theme,
      link: req.url,
      posts: posts,
    });
  })
});

app.get('/searching', function (req, res) {
  res.type('json')
  res.end(JSON.stringify(usersname));
});

app.route("/search")
  .get(checkAuthenticated, function (req, res) {
    res.render("posts/search", {
      dark: req.user.dark_theme,
      link: req.url,
    })
  })
  .post(function (req, res) {
    const search = req.body.search;
    User.findOne({
      username: search
    }, function (err, item) {
      if (err) throw err;
      if (item.email != "theblogpostbyshivam@gmail.com") {
        res.redirect("/profile/" + item._id)
      } else {
        res.render("posts/404", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
    })
  })
app.route("/post/:postid")
  .get(checkAuthenticated, function (req, res) {
    Post.findOne({
      _id: req.params.postid
    }, function (err, post) {
      if (err) {
        res.render("posts/404", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
      if (post) {
        User.findOne({
          _id: post.authorID
        }, function (err, author) {
          if (err) {
            res.render("posts/404", {
              dark: req.user.dark_theme,
              link: req.url
            })
          }
          res.render("posts/post", {
            dark: req.user.dark_theme,
            link: req.url,
            post: post,
            author: author,
            edit: req.user.email,
            user: req.user._id
          })
        })
      }
    })
  })
  .post(function (req, res) {
    Post.findOne({
      _id: req.params.postid
    }, function (err, post) {
      if (err) {
        res.render("posts/404", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
      if (post) {
        if (post.like.includes(req.user._id)) {
          Post.updateOne({
              _id: req.params.postid
            }, {
              $pull: {
                like: req.user._id
              }
            },
            function (err) {
              if (err) throw err;
            })
        } else {
          Post.updateOne({
              _id: req.params.postid
            }, {
              $push: {
                like: req.user._id
              }
            },
            function (err) {
              if (err) throw err;
            })
        }
        res.redirect("/post/" + post._id);
      }
    })
  })


app.get("/profile", checkAuthenticated, function (req, res) {
  Post.find({
    authorID: req.user._id
  }, function (err, posts) {
    res.render("posts/profile", {
      dark: req.user.dark_theme,
      link: req.url,
      user: req.user.username,
      email: req.user.email,
      bio: req.user.bio,
      img: req.user.dp,
      posts: posts,
    });
  })
});

app.route("/profile/edit")
  .get(checkAuthenticated, function (req, res) {
    res.render("posts/editprofile", {
      dark: req.user.dark_theme,
      link: req.url,
      name: req.user.username,
      bio: req.user.bio,
      img: req.user.dp,
    })
  })
  .post(upload, function (req, res) {
    fs.stat("./public/uploads/image", function (err, stats) {
      if (err) {
        User.updateOne({
          email: req.user.email
        }, {
          username: req.body.username,
          bio: req.body.bio,
        }, function (err) {
          if (err) throw err;
          res.redirect("/profile")
        })
      }
      if (stats) {
        Jimp.read("./public/uploads/image", function (err, image) {
          if (err) throw err;
          image.cover(500, 500).write(__dirname + "/public/user/" + req.user._id + ".jpg");
        })
        User.updateOne({
          email: req.user.email
        }, {
          username: req.body.username,
          bio: req.body.bio,
          dp: req.user._id + ".jpg"
        }, function (err) {
          if (err) throw err;
          res.redirect("/profile")
        })
      }
    })
  })

app.get("/profile/edit/removedp", checkAuthenticated, function (req, res) {
  fs.unlink("./public/user/" + req.user.dp, function (err) {
    if (err && err.code == 'ENOENT') throw err;
  })
  User.updateOne({
    email: req.user.email
  }, {
    dp: "default.svg"
  }, function (err) {
    if (err) throw err;
    res.redirect("/profile/")
  })
})

app.get("/theme", checkAuthenticated, function (req, res) {
  User.updateOne({
    email: req.user.email
  }, {
    $set: {
      dark_theme: !req.user.dark_theme
    }
  }, function (err) {
    if (err) throw err;
  })
  res.redirect("/profile")
})

app.get("/admin", checkAuthenticated, function (req, res) {
  if (req.user.email == "theblogpostbyshivam@gmail.com") {
    User.find({}, function (err, authors) {
      if (err) throw err;
      res.render("posts/admin", {
        dark: req.user.dark_theme,
        link: req.url,
        authors: authors,
      })
    })
  } else {
    res.render("posts/access", {
      dark: req.user.dark_theme,
      link: req.url
    })
  }
})


app.get("/about", function (req, res) {
  if (req.user) {
    res.render("posts/about", {
      dark: req.user.dark_theme,
      link: req.url
    })
  } else {
    res.render("posts/about", {
      dark: false,
      link: req.url
    })

  }
})

app.get("/profile/:authorid", checkAuthenticated, function (req, res) {
  if (req.params.authorid == req.user._id) {
    res.redirect("/profile");
  } else {
    User.findOne({
      _id: req.params.authorid
    }, function (err, author) {
      if (err) {
        res.render("posts/404", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
      if (author) {
        Post.find({
          authorID: req.params.authorid
        }, function (err, posts) {
          res.render("posts/author", {
            dark: req.user.dark_theme,
            link: req.url,
            author: author,
            posts: posts,
          })
        })
      }
    })
  }
})

app.route("/compose")
  .get(checkAuthenticated, function (req, res) {
    res.render("posts/compose", {
      dark: req.user.dark_theme,
      link: req.url,
      title: "",
      content: "",
      redlink: "/"
    });
  })
  .post(function (req, res) {
    var {
      postTitle,
      postBody,
    } = req.body;
    const formatted = new Date().toLocaleString('en-US', {
      timeZone: 'Asia/Kolkata',
      hour12: true,
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
    const newPost = new Post({
      authorID: req.user._id,
      title: postTitle,
      content: postBody,
      time: formatted,
    });
    newPost.save(function (err) {
      if (err) throw err;
      req.flash("success_message", "New post up!");
      res.redirect("/");
    });
  });


app.route("/compose/:postid")
  .get(checkAuthenticated, function (req, res) {
    Post.findOne({
      _id: req.params.postid
    }, function (err, post) {
      if (err) {
        res.render("posts/404", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
      if (post) {
        if (post.authorID == req.user._id || req.user.email == "theblogpostbyshivam@gmail.com") {
          res.render("posts/compose", {
            dark: req.user.dark_theme,
            link: req.url,
            title: post.title,
            content: post.content,
            redlink: "/post/" + req.params.postid
          });
        } else {
          res.render("posts/access", {
            dark: req.user.dark_theme,
            link: req.url
          })
        }
      }
    })
  })
  .post(function (req, res) {
    const formatted = new Date().toLocaleString('en-US', {
      timeZone: 'Asia/Kolkata',
      hour12: true,
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
    Post.updateOne({
      _id: req.params.postid
    }, {
      title: req.body.postTitle,
      content: req.body.postBody,
      time: formatted,
    }, function (err) {
      if (err) throw err;
      res.redirect("/post/" + req.params.postid)
    })
  })

app.get("/delete/:postid", checkAuthenticated, function (req, res) {
  Post.findOne({
    _id: req.params.postid
  }, function (err, post) {
    if (err) {
      res.render("posts/404", {
        dark: req.user.dark_theme,
        link: req.url
      })
    }
    if (post) {
      if (post.authorID == req.user._id || req.user.email == "theblogpostbyshivam@gmail.com") {
        Post.deleteOne({
          _id: post._id
        }, function (err) {
          if (err) throw err;
          res.redirect("/");
        })
      } else {
        res.render("posts/access", {
          dark: req.user.dark_theme,
          link: req.url
        })
      }
    }
  })
})


app.route("/logout")
  .get(function (req, res) {
    req.logout();
    res.redirect("/login");
  })

app.listen(process.env.PORT);