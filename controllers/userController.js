import userModel from "../models/userModel.js";
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import validator from 'validator'



const createToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET)
}



// -----------------L O G I N  U S E R --------------------

const loginUser = async (req, res)=>{
    const {email, password} = req.body;
   try {
    //USER EXIST CHECK
    const user = await userModel.findOne({email })
    if(!user){
        return res.json({success:false,message:"Email not found"})
    }

    //DECCRYPT PASSWORD
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if(!isPasswordMatch){
        return res.json({success:false, message:"Invalid Credentials"})
    }
     
    //TOKEN
    const token = createToken(user._id);
    res.json({success:true, token})
    
    //ERROR
   } catch (error) {
    console.log(error);
    res.json({success: false,message:"error"})
    
   }
}


// ----------R E G I S T E R   U S E R ----------------------------
const registerUser = async (req, res) => {
    const {name, password, email} = req.body;
    try {
        // USER EXIST CHECK
        const userExist = await userModel.findOne({email})
        if(userExist){
            return res.json({success:false, message:"User Already Exist"})
        }

        //EMAIL VALIDATION
        if(!validator.isEmail(email)){
           return res.json({success:false, message:"Please Enter Valid Email"})
        }

        //PASSWORD VALIDATION
        if(password.length<8){
            return res.json({success:false, message:"Please Enter a Strong Password"})
        }

        //PASSWORD HASHING
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)

        //NEW USER
        const newUser = new userModel({
            name: name,
            email: email,
            password: hashedPassword,
        })
        const user = await newUser.save()
        const token = createToken(user._id )
        res.json({success:true, token})

        //ERROR
    } catch (error) {
        console.log(error);
        res.json({success:false, message: "error"})
        
    }
}

export {loginUser, registerUser}