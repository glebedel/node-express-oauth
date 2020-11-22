const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios').default;
const { randomString, timeout } = require('./utils');

const config = {
  port: 9000,

  clientId: 'my-client',
  clientSecret: 'zETqHgl0d7ThysUqPnaFuLOmG1E=',
  redirectUri: 'http://localhost:9000/callback',

  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
  userInfoEndpoint: 'http://localhost:9002/user-info',
};
let state = '';

const app = express();
app.set('view engine', 'ejs');
app.set('views', 'assets/client');
app.use(timeout);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/authorize', (req, res) => {
  state = randomString();
  const redirectUrl = new URL(config.authorizationEndpoint);
  const searchParams = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: 'permission:name permission:date_of_birth',
    state: state,
  });
  redirectUrl.search = searchParams.toString();
  return res.redirect(redirectUrl.toString());
});

app.get('/callback', async (req, res) => {
  if (!state || state !== req.query.state) {
    return res.status(403).end();
  }
  const tokenRequest = await axios.post(
    config.tokenEndpoint,
    { code: req.query.code },
    { auth: { username: config.clientId, password: config.clientSecret } },
  );
  const accesstoken = tokenRequest.data.access_token;
  const userInfoRequest = await axios.get(config.userInfoEndpoint, {
    headers: { authorization: `bearer ${accesstoken}` },
  });
  return res.render('welcome', { user: userInfoRequest.data });
});

const server = app.listen(config.port, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
});

// for testing purposes

module.exports = {
  app,
  server,
  getState() {
    return state;
  },
  setState(s) {
    state = s;
  },
};
