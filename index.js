import express from "express";
import jwt from 'jsonwebtoken'
import { PORT } from "./config.js";
import { SECRET_JWT_KEY } from "./config.js";
import { UserRepository } from "./user-repository.js";
import cookieParser from "cookie-parser";
import { use } from "bcrypt/promises.js";

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())


app.get('/', (req, res) => {
    res.render('index')
})

app.post('/login', async(req, res) => {
    const { username, password } = req.body
    console.log(req.body)
    try{
        const user = await UserRepository.login({username,password})
        const token = jwt.sign(
            {id: user._id, username: user.username}, 
            SECRET_JWT_KEY,
            {
                expiresIn: '1h'
            })
        res
        .cookie('access_token',token,{
            httpOnly: true, //la cookie solo se puede acceder desde el servidor
            secure: process.env.NODE_ENV == 'production', // la cookie solo se puede acceder en https
            sameSite: 'strict', // Solo se puede acceder desde el mismo dominio
            maxAge: 100 * 60 * 60 // la cookie solo tiene validez de 1 hora
        })
        .send({user,token})
    } catch (error){
        res.status(401).send(error.message)
    }
})
app.post('/register', async(req, res) => {
    const { username, password } = req.body
    console.log(req.body)
    try {
        const id = UserRepository.create ({username,password})
        res.send({id})
    } catch(error){
        res.status(400).send(error.message)
    }
})
app.post('/logout', (req, res) => {})

app.get('/protected', (req, res) => {})

app.listen(PORT, () =>{
    console.log(`Server running on port ${PORT}`)
})
