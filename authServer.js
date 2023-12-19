require("dotenv").config()
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken")

const express = require('express')
const app = express()
app.use(express.json())

const port = process.env.TOKEN_SERVER_PORT

app.listen(port, () => {
    console.log(`Authorization Server running on ${port}...`)
})

const users = []
let refreshTokens = []

app.get("/ping", async (req, res) => {
    res.send("pong")
})

app.post("/createUser", async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    users.push({ username: req.body.username, password: hashedPassword })
    res.status(201).send(users)
})

app.post("/login", async (req, res) => {
    const username = users.find((c) => c.username == req.body.username)

    if (username == null) {
        res.status(404).send("User does not exist!")
    }

    if (!await bcrypt.compare(req.body.password, username.password)) {
        res.status(401).send("Password Incorrect!")
    }

    const accessToken = generateAccessToken({ username })
    const refreshToken = generateRefreshToken({ username })

    res.json({ accessToken, refreshToken })

})

app.post("/refreshToken", (req, res) => {

    if (!refreshTokens.includes(req.body.token)) {
        res.status(400).send("Refresh Token Invalid")
    }

    const username = req.body.username

    //remove the old refreshToken from the refreshTokens list
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)

    //generate new accessToken and refreshTokens
    const accessToken = generateAccessToken({ username })
    const refreshToken = generateRefreshToken({ username })

    res.json({ accessToken, refreshToken })
})

app.delete("/logout", (req, res) => {

    //remove the old refreshToken from the refreshTokens list
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)
    res.status(204).send("Logged out!")

})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" })
}

function generateRefreshToken(user) {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "20m" })
    refreshTokens.push(refreshToken)
    return refreshToken
}