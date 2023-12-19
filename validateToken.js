const jwt = require("jsonwebtoken")
const express = require("express")
require("dotenv").config()

const app = express()
const port = process.env.PORT

app.use(express.json())

app.listen(port, () => {
    console.log(`Validation server running on ${port}...`)
})

app.get("/posts", validateToken, (req, res) => {
    return res.send(`${req.user.username} successfully accessed post`)
})

function validateToken(req, res, next) {

    const authHeader = req.headers["authorization"]

    // The request header contains the token "Bearer <token>", split the string and use the second value in the split array.
    const token = authHeader.split(" ")[1]

    if (token == null) {
        res.sendStatus(400).send("Token not present")
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {

        if (err) {
            return res.status(403).send("Token invalid")
        }

        req.user = user
        next()
    })
} 