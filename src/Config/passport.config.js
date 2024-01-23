import passport from "passport";
import passportlocal from "passport-local";
import UserModel from "../models/user.js";
import { createHash, isValidPassword} from "../dirname.js";


const localStrategy = passportlocal.Strategy

const initializePassport =()=>{

  passport.use("register", new localStrategy(
    {passReqToCallback: true, usernameField: "email"},
    
    async (req, username, password, done) =>{
      const {first_name, last_name, email,age} = req.body;
      try{
        const exist = await UserModel.findOne({email});
        if(exist){
          console.log("El user ya existe!!");
          done(null,false)
        }

        const user={
          first_name,
          last_name,
          email,
          age,
          password:createHash(password)
        }
        const result = await UserModel.create(user);
        return done (null, result)
      }catch(error){
        return done("Error registrando al usuario " + error);
      }
    }
  ))


  passport.use("login", new localStrategy(
    {passReqToCallback: true, usernameField: "email"},

    async(req, username, password, done)=>{
      try{
        const user = await UserModel.findOne({email:username});
        if (!user) {
          console.warn("User doesn't exists with username: " + username);
          return done(null, false);
        }
        if (!isValidPassword(user, password)) {
            console.warn("Invalid credentials for user: " + username);
            return done(null, false);
        }
        return done(null, user);

      }catch{
        return done(error);
      }
    }

  ));

  //Funciones de Serializacion y Desserializacion
  passport.serializeUser((user, done) => {
    done(null, user._id)
  })

  passport.deserializeUser(async (id, done) => {
    try {
        let user = await UserModel.findById(id);
        done(null, user)
    } catch (error) {
        console.error("Error deserializando el usuario: " + error);
    }
  })
}

export default initializePassport;