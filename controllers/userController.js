import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import res from "express/lib/response.js";
import jwt from "jsonwebtoken";
import transporter from "../config/emailConfig.js";

export const userRegistration = async (req, res) => {
  const { name, email, password, password_confirmation, tc } = req.body;
  const user = await UserModel.findOne({ email: { $eq: email } });
  if (user) {
    res.send({ status: "failed", message: "Email already exists" });
  }
  if (name && email && password && password_confirmation && tc) {
    if (password === password_confirmation) {
      try {
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        const doc = new UserModel({
          name: name,
          email: email,
          password: hashPassword,
          tc: tc,
        });
        await doc.save();
        const saved_user = await UserModel.findOne({ email: email });
        //JWT TOKEN RETURN
        const token = jwt.sign(
          { userID: saved_user._id },
          process.env.JWT_SECRET_KEY,
          { expiresIn: "5d" }
        );
        res.status(201).send({
          status: "Success",
          message: "Registered Successfully",
          token: token,
        });
      } catch (err) {
        console.log(err);
        res.send({ status: "400", message: "Cannot Register" }); // not for production
      }
    } else {
      res.send({
        status: "failed",
        message: "Password and confirm password doesnt match",
      });
    }
  } else {
    res.send({ status: "failed", message: "All fields are required" });
  }
};

export const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email && password) {
      const user = await UserModel.findOne({ email: { $eq: email } });

      if (user != null) {
        const isMatched = await bcrypt.compare(password, user.password);
        console.log(isMatched);
        if (isMatched) {
          //JWT RETURN
          const saved_user = await UserModel.findOne({ email: email });
          const token = jwt.sign(
            { userID: saved_user._id },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "5d" }
          );
          res.status(200).send({
            token: token,
            status: "Success",
            message: "Login Success",
          });
        } else {
          res.send({
            status: "Failed",
            message: "Email or password not valid",
          });
        }
      } else {
        res.send({ status: "Failed", message: "Not a registered user" });
      }
    } else {
      res.send({ status: "Failed", message: "All fields are required" });
    }
  } catch (error) {
    console.log(error);
  }
};

export const changeUserPassword = async (req, res) => {
  const { password, password_confirmation } = req.body;
  if (password && password_confirmation) {
    if (password === password_confirmation) {
      const salt = await bcrypt.genSalt(10);
      const hashPassword = await bcrypt.hash(password, salt);
      await UserModel.findByIdAndUpdate(req.user._id, {
        $set: { password: hashPassword },
      });
      res.send({ Status: "success", message: "Password chaned successfully" });
    } else {
      res.send({
        status: "Failed",
        message: "Password and Confirm Password didnt match",
      });
    }
  } else {
    res.send({ status: "Failed", message: "All fields are required" });
  }
};

export const loggedUser = async (req, res) => {
  res.send({ user: req.user });
};

export const sendPwResetEmail = async (req, res) => {
  const { email } = req.body;
  if (email) {
    const user = await UserModel.findOne({ email: email });
    if (user) {
        const secret=user._id + process.env.JWT_SECRET_KEY
        const token=jwt.sign({userID:user._id},secret,{expiresIn:'150m'})
        const link=`http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`
        res.send({ status: "success", message: "Check your email to reset password" });
        console.log(link)
        let info=await transporter.sendMail({
          from:process.env.EMAIL_FROM,
          to:user.email,
          subject:"Reset Password",
          html:`<a href=${link}>Click here to Reset Password</a>`
        })


    } else {
      res.send({ status: "failed", message: "Email is Required" });
    }
  } else {
    res.send({ status: "failed", message: "Email is Required" });
  }
};


export const userPasswordReset= async (req,res)=>{
  const {password,password_confirmation}=req.body
  const {id,token}=req.params
  const user=await  UserModel.findById(id)
  const new_secret = user._id + process.env.JWT_SECRET_KEY
  try{
    jwt.verify(token,new_secret)
    if(password && password_confirmation){
       if (password === password_confirmation){
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        await UserModel.findByIdAndUpdate(user._id, {
          $set: { password: hashPassword },
        });
         res.send({"status":"Success","message":"Password Reset Successful"})
         
        }
        else{
         res.send({"status":"Failed","message":"Password and confirm password doesnt match"})

       }
    }
    else{
      res.send({"status":"Failed","message":"Both fields are required"})

    }
  }
catch(error){
  res.send({"status":"Failed","message":"Invalid token"})
}


}





