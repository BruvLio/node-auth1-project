const router = require("express").Router();
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");
const {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("./auth-middleware");

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  //eslint-disable-next-line
  async (req, res, next) => {
    let { password } = req.body;
    req.body.password = bcrypt.hashSync(password, 10);
    let newGuy = await Users.add(req.body);
    res.status(200).json(newGuy);
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post("/login", checkUsernameExists, async (req, res, next) => {
  let { username, password } = req.body;
  let [user] = await Users.findBy({ username });
  // console.log(user);
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user;
    // console.log(user);
    res.status(200).json({
    message: `Welcome ${user.username}!`,
    });
  } else {
    res.status(401).json({ message: "Invalid Credentials" });
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }

 */
//eslint-disable-next-line
router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        req.json({ message: `You can never leave` });
      } else {
        res.set(
          "Set-Cookie",
          "chocolatechip=; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00'"
        );
        res.status(200).json({ message: "logged out" });
      }
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
