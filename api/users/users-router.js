// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require("express");

const Users = require("./users-model");

const router = express.Router();

router.get("/", async (req, res, next) => {
  // console.log(`made it to users router`);
  try {
    const users = await Users.find();
    res.status(200).json(users);
  } catch (err) {
    next(err);
  }
});
/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */

module.exports = router;
// Don't forget to add the router to the `exports` object so it can be required in other modules
