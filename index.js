// Modules utilisé pour le projet
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const email_validator = require('email-validator');

// Configuration afin de pouvoir utiliser le fichier .env
dotenv.config();

// console.log(email_validator.validate("Jonathan.Lamontagne@pinartEE.onmicrosoft.com"));

const app = express();
const port = 8000;

// Middleware utilisé pour tous les endpoint
app.use(cors());
app.use(express.json());

// Configuration de la connection à la base de donnée en utilisant le fichier .env
const db = mysql.createConnection({
    host: process.env.SQL_HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASSWORD,
    database: process.env.SQL_DATABASE
}).promise();

// Connection à la base de donnée
db.connect();

// Middleware pour vérifier si les information de l'utilisateur sont valide lors de la création d'utilisateur
async function verifyUserCredValid(req, res, next){
    let name = req.body.name;
    let password = req.body.password;
    let role = req.body.role;
    let email = req.body.email;

    var userCredValid = false;
    var emailValid = false;
    var nameValid = false;
    var roleValid = false;
    var passwordValid = false;

    var resError = [];

    // Validation du courriel
    if (email_validator.validate(email)) {
        let queryString = "SELECT email FROM users WHERE email = ?";
        let [existingEmail] = await db.query(queryString,email);

        if(existingEmail.length === 0) {
            emailValid = true;
        } else {
            resError.push("emailError:'Email already exist in the database'");
        }
    } else {
        resError.push("emailError:'Email not valid'");
    }

    // Validation du nom
    if (name != null) {
        if (name.length <= 255) {
            nameValid = true;
        } else {
            resError.push("nameError:'Name length most not be longer than 255 characters'");
        }
    } else {
        resError.push("nameError:'Name is required to create a user'");
    }

    // Validation du role
    if (role != null) {
        if (role == "admin" || role == "read-only" || role == "editor") {
            roleValid = true;
        } else {
            resError.push("roleError:'Invalid role'");
        }
    } else {
        resError.push("roleError:'A role is required'");
    }

    // Validation du mots de passes
    if (password != null) {
        if (password.length <= 255) {
            passwordValid = true;
        } else {
            resError.push("passwordError:'Password length most not be longer than 255 characters'")
        }
    } else {
        resError.push("passwordError:'Password is required")
    }

    // Vérification que tous les champs son valide
    if (emailValid && nameValid && roleValid && passwordValid) {
        userCredValid = true;
    }

    // Si tous les champs son valide continue vers le endpoint suivant sinon envoi une erreur en réponse à la requête
    if (userCredValid) {
        next();
    } else {
        res.status(400).send(resError);
    }
}

// Middleware pour verifier token. Nécessite un token de niveau "read-only" au minimum
function verifySimpleToken(req,res,next) {

    if (req.headers.authorization !== undefined) {
        
        // Recuperer le token venant de la requête
        let token = req.headers.authorization.split(" ")[1];
        // Vérifie si le token est valide en partant du plus haut niveau de sécurité jusqu'au plus bas. Quitte la boucle dès qu'un token valide est trouver.
        for (let i = 0; i < 3; i++) {
            if (i == 0) {
                jwt.verify(token, process.env.JWT_ADMIN, (err,data) => {
                    if (!err) {
                        next();
                        i = 3;
                    }
                })
            } else if (i == 1) {
                jwt.verify(token, process.env.JWT_EDITOR, (err,data) => {
                    if (!err) {
                        next();
                        i = 3;
                    }
                })
            } else {
                jwt.verify(token, process.env.JWT_READONLY, (err,data) => {
                    if (!err) {
                        next();
                    } else {
                        res.status(403).send({message: "Invalid Token"});
                    }
                })
            } 
        }

    } else {
        res.send({message: "Please send a token"});
    }

}

// Middleware pour verifier token. Nécessite un token de niveau "editor" au minimum
function verifyToken(req,res,next) {

    if (req.headers.authorization !== undefined) {
        
        // Recuperer le token venant de la requête
        let token = req.headers.authorization.split(" ")[1];
        // Vérifie si le token est valide en partant du plus haut niveau de sécurité jusqu'au plus bas. Quitte la boucle dès qu'un token valide est trouver.
        for (let i = 0; i < 2; i++) {
            if (i == 0) {
                jwt.verify(token, process.env.JWT_ADMIN, (err,data) => {
                    if (!err) {
                        next();
                        i = 2;
                    }
                })
            } else {
                jwt.verify(token, process.env.JWT_EDITOR, (err,data) => {
                    if (!err) {
                        next();
                    } else {
                        res.status(403).send({message: "Invalid Token"});
                    }
                })
            }
        }

    } else {
        res.send({message: "Please send a token"});
    }
}

// Middleware pour verifier token. Nécessite un token de niveau "admin" au minimum
function verifyMaxSecurityToken(req,res,next) {

    if (req.headers.authorization !== undefined) {
        // Recuperer le token venant de la requête
        let token = req.headers.authorization.split(" ")[1];

        jwt.verify(token, process.env.JWT_ADMIN, (err,data) => {
            if (!err) {
                next();
            } else {
                res.status(403).send({message: "Invalid Token"});
            }
        })

    } else {
        res.send({message: "Please send a token"});
    }
}

// Endpoint pour enregistrer un nouvel utilisateur dans la base de donnée
app.post("/register", verifyUserCredValid, (req,res)=> {
    let name = req.body.name;
    let password = req.body.password;
    let role = req.body.role;
    let email = req.body.email;

    let queryString = "INSERT into users (name, password, role, email) VALUES(?,?,?,?)";

    // Enregistrement dans la base de donnée
    try {
        // Hashage du mots de passe afin qu'il ne sois pas visible pour tous
        bcrypt.genSalt(10,(err,salt)=>{
            if (!err){
                bcrypt.hash(password,salt, async (err,hpass)=>{
                    if (!err) {
                        password = hpass;
                        await db.query(queryString, [name, password, role, email]);
                        res.status(201).send({message:"User " + name + " create sucessfully"})
                    }
                })
            }
        });
    } catch (err) {
        res.status(500).send({message:"Error: " + err})
    }
})

app.post("/login", async (req,res)=> {
    let userCred = req.body;

    try {
        let queryString = "SELECT * FROM users WHERE email = ?";
        let [user] = await db.query(queryString,userCred.email);
        // Information reviens en tant que object JSON à l'intérieur d'un Array alors on sort l'object de l'array afin de pouvoir utiliser les données.
        let userData = user.pop();

        if (userData != null) {
            // Comparer le mots de passe hasher entreposé dans la base de donnée avec le mots de passe envoyer par l'utilisateur
            bcrypt.compare(userCred.password, userData.password, (err, success) => {
                if (success == true) {
                    // Vérifie si le role de l'utilisateur est admin et génère un token de niveau admin
                    if (userData.role == "admin") {
                        jwt.sign({email:userCred.email}, process.env.JWT_ADMIN, (err, token) => {
                            if (!err) {
                                res.send({message: "Login Sucessfully", token:token});
                            }
                        })
                    }
                    // Vérifie si le role de l'utilisateur est read-only et génère un token de niveau read-only
                    if (userData.role == "read-only") {
                        jwt.sign({email:userCred.email}, process.env.JWT_READONLY, (err, token) => {
                            if (!err) {
                                res.send({message: "Login Sucessfully", token:token});
                            }
                        })
                    }
                    // Vérifie si le role de l'utilisateur est editor et génère un token de niveau editor
                    if (userData.role == "editor") {
                        jwt.sign({email:userCred.email}, process.env.JWT_EDITOR, (err, token) => {
                            if (!err) {
                                res.send({message: "Login Sucessfully", token:token});
                            }
                        })
                    }
                } else {
                    res.status(403).send({message: "Password Incorrect"});
                }
            })
        } else {
            res.status(404).send({message: "User not found"});
        }

    } catch (err) {
        res.status(500).send({message: "Some Problem"});
    }
    
})

// Endpoint pour aller chercher tous les utilisateurs
app.get("/users", async (req,res) => {
    let querryString = "SELECT * FROM users";
    
    try {
        let [users] = await db.query(querryString);
        res.send(users);
    } catch (err) {
        res.status(500).send({message: "An error occurred when you tried to get all the users"})
    }
    
})

// Endpoint pour aller un utilisateur en utilisant son id comme réfférence
app.get("/users/:id", async (req,res) => {
    let userId = req.params.id;
    let querryString = "SELECT * FROM users WHERE id = ?";

    try {
        let [user] = await db.query(querryString, userId);
        if (user.length == 0) {
            res.status(404).send({message: "User not found"});
        } else {
            res.send(user);
        }
        
    } catch (err) {
        res.status(500).send({message: "An error occurred when you tried to get the users " + userId});
    }
})

// Endpoint pour supprimer un utilisateur selon un id. Utilise le middleware verifiant le token à sécuriter maximal (admin)
app.delete("/users/:id", verifyMaxSecurityToken, async (req,res) => {
    let userId = req.params.id;
    let querryString = "DELETE FROM users WHERE id = ?";

    try {
        await db.query(querryString, userId);
        res.send({message: "user delete successfully"});
    } catch (err) {
        res.status(500).send({message: "An error occurred when you tried to delete the user"})
    }
})

app.get("/test", verifySimpleToken, (req,res) => {
    console.log("we got there")
})

app.listen(port, () => {
    console.log(`API running on port ${port}`);
})