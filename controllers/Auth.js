const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// Signup route handler
exports.signup = async(request,response) => {
    try {
        // Get data
        const {name,email,password,role} = request.body;
        
        // Check if user already exist
        const existingUser = await User.findOne({email});
        if(existingUser) {
            return response.status(400).json({
                success:false,
                message:'User already Exist!',
            });
        }

        // Secure password
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password,10);
        }
        catch(error) {
            return response.status(500).json({
                success:false,
                message:'Error in hashing Password',
            });
        }

        // Create entry for User
        const user = await User.create({
            name,email,password:hashedPassword,role
        })
        return response.status(200).json({
            success:true,
            message:'User Created Successfully',
        });
    }
    catch(error) {
        console.error(error); 
        return response.status(500).json({
            success:true,
            message:'User cannot be registered, please try again later',
        });
    }
}


// Login route handler
exports.login = async (request,response) => {
    try {
        // Data Fetch
        const {email,password} = request.body;

        // Validation on email and password
        if(!email || !password) {
            return response.status(400).json({
                success:false,
                message:'Please fill all the details carefully',
            });
        }

        // Check for registered user
        let user = await User.findOne({email});

        // If not a registered user
        if(!user) {
            return response.status(401).json({
                success:false,
                message:'User is not registered!',
            });
        }

        const payload = {
            email:user.email,
            id:user._id,
            role:user.role,
        };
        // Verify password & generate a JWT token
        if(await bcrypt.compare(password,user.password)) {
            // Password match
            let token = jwt.sign(payload,
                process.env.JWT_SECRET,{expiresIn:"2h",});

            user = user.toObject();
            user.token = token;
            user.password = undefined;
            
            const options = {
                expires:new Date( Date.now() + 3 * 24 * 60 * 60 *1000),
                httpOnly:true,
            }

            response.cookie("kasanaCookie", token, options).status(200).json({
                success:true,
                token,
                user,
                message:'User Logged in successfully',
            });
        }
        else {
            // Password do not match
            return response.status(403).json({
                success:false,
                message:'Password Incorrect',
            });
        }
    }
    catch(error) {
        console.log(error);
        return response.status(500).json({
            success:false,
            message:'Login Failure',
        });
    }
}