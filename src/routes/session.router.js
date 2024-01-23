import { Router } from "express";
import UserModel from "../models/user.js";
import { createHash, isValidPassword } from "../dirname.js";
import passport from "passport";


const router = Router()

router.post('/register', passport.authenticate("register", {
  failureRedirect: "api/session/fail-register"
}), async (req,res)=>{

res.send({status:"success", msg:"User created"})
})


router.post('/login', passport.authenticate("login", {
  failureRedirect: "api/session/fail-login"
}), async (req,res) => {
  // let rol;
  // if(email == "adminCoder@coder.com" && password == "adminCod3r123"){
  //     rol = "admin"
  // }
  // else{
  //     rol = "user"
  // }
  const user = req.user;
  const rol = "user"

  req.session.user = {
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
      age: user.age,
      rol: rol
  }

  res.send({status:'success', payload: req.session.user, message:'Log successful'})
})

router.get('/logout',  (req,res)=>{
  req.session.destroy(err =>{
    if(!err) return res.status(200).send("deslogueo exitoso")
    else res.send("fallo el deslogueo")
  })
})
export default router;