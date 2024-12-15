const express = require("express");
const router = express.Router();

const {login, signup} = require("../controllers/Auth");
const {auth, isStudent, isAdmin} = require("../middlewares/auth");

router.post("/login", login);
router.post("/signup", signup);

// Testing protected routes for single middleware
router.get("/test", auth, (request,response) => {
    response.json({
        success:true,
        message:'Welcome to the Protected route for Test',
    });
})

// Protected Route
router.get("/student", auth, isStudent, (request,response) => {
    response.json({
        success:true,
        message:'Welcome to the Protected route for Students',
    });
})

router.get("/admin", auth, isAdmin, (request,response) => {
    response.json({
        success:true,
        message:'Welcome to the Protected route for Admin',
    });
})

module.exports = router;