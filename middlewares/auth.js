const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = (request,response,next) => {
    try {
        // Extract JWT Token
        const token = request.cookies.token || request.body.token || request.header("Authorization").replace("Bearer ", "");
        if(!token || token === undefined) {
            return response.status(401).json({
                success:false,
                message:'Token Missing',
            });
        }

        // Verify the Token
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            console.log(payload);
            request.user = payload;
        }
        catch(error) {
            return response.status(401).json({
                success:false,
                message:'Token is Invalid',
            });
        }
        next();
    }
    catch(error) {
        return response.status(401).json({
            success:false,
            message:'Something went wrong, while verifying the token',
        });
    }
}

exports.isStudent = (request,response,next) => {
    try {
        if(request.user.role !== "Student") {
            return response.status(401).json({
                success:false,
                message:'This is a protected route for students',
            });
        }
        next();
    }
    catch(error) { 
        return response.status(500).json({
            success:false,
            message:'User Role is not matching', 
        });
    }
}

exports.isAdmin = (request,response,next) => {
    try {
        if(request.user.role !== "Admin") {
            return response.status(401).json({
                success:false,
                message:'This is protected route for Admin',
            });
        }
        next();
    }
    catch(error) {
        return response.status(500).json({
            success:false,
            message:'User Role is not matching',
        });
    }
}