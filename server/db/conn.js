const mongoose = require("mongoose");

const DB = "mongodb+srv://pratikkate29:u290l7fwvn5k2vO7@cluster0.czwmjb9.mongodb.net/Authusers?retryWrites=true&w=majority&appName=Cluster0"

mongoose.connect(DB,{
 
}).then(()=> console.log("Database Connected"))
   .catch((err)=>{
    console.log(err);
})