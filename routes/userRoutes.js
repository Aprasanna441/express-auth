import  express from "express";
const router=express.Router()
// import {userRegistration} from '../controllers/userController.js'
import { userLogin,userRegistration,changeUserPassword,loggedUser ,sendPwResetEmail,userPasswordReset} from "../controllers/userController.js";
import checkUserAuth from "../middlewares/auth-middleware.js"

//middleware
router.use('/changepassword',checkUserAuth)
router.get('/loggeduser',checkUserAuth)


//public routes 
router.post('/register',userRegistration)
router.post('/login',userLogin)
router.post('/send-resetpasswordmail',sendPwResetEmail)
router.post('/reset/:id/:token',userPasswordReset)

//protected routes 
router.post('/changepassword',changeUserPassword)
router.get('/loggeduser',loggedUser)



export default router