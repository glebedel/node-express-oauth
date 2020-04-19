const url = require("url")
const express = require("express")
const bodyParser = require("body-parser")
const axios = require("axios").default
const { randomString } = require("./utils")

const config = {
	port: 9000,

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
}
let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/client")
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", (req, res) => {
	state = randomString()
	const redirectUrl = url.parse(config.authorizationEndpoint)
	redirectUrl.query = {
		response_type: "code",
		client_id: config.clientId,
		client_secret: config.clientSecret,
		redirect_uri: config.redirectUri,
		scope: "name dob",
		state: state,
	}
	res.redirect(url.format(redirectUrl))
})

app.get("/callback", (req, res) => {
	if (req.query.state !== state) {
		res.status(403).send("Error: state mismatch")
		return
	}

	const { code } = req.query
	axios({
		method: "POST",
		url: config.tokenEndpoint,
		auth: {
			username: config.clientId,
			password: config.clientSecret,
		},
		data: {
			code,
		},
	}).then((response) => {
		if (response.status !== 200) {
			res.status(500).send("Error: something went wrong")
			return
		}

		res.render("welcome", { token: response.data.access_token })
	})
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
	console.log("OAuth Client is listening at http://%s:%s", host, port)
})
