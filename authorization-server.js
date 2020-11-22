const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { randomString, containsAll, decodeAuthCredentials, timeout } = require('./utils');

const config = {
  port: 9001,
  privateKey: fs.readFileSync('assets/private_key.pem'),
  clientId: 'my-client',
  clientSecret: 'zETqHgl0d7ThysUqPnaFuLOmG1E=',
  redirectUri: 'http://localhost:9000/callback',
  authorizationEndpoint: 'http://localhost:9001/authorize',
};

const clients = {
  'my-client': {
    name: 'Sample Client',
    clientSecret: 'zETqHgl0d7ThysUqPnaFuLOmG1E=',
    scopes: ['permission:name', 'permission:date_of_birth'],
  },
  'test-client': {
    name: 'Test Client',
    clientSecret: 'TestSecret',
    scopes: ['permission:name'],
  },
};

const users = {
  user1: 'password1',
  john: 'appleseed',
};

const requests = {};
const authorizationCodes = {};

let state = '';

const app = express();
app.set('view engine', 'ejs');
app.set('views', 'assets/authorization-server');
app.use(timeout);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/authorize', (req, res) => {
  const clientId = req.query.client_id;
  if (clients.hasOwnProperty(clientId)) {
    const client = clients[clientId];
    const reqScopes = (req.query.scope || '').split(' ');
    // verify that all scopes requested are valid for this clientId
    if (containsAll(client.scopes, reqScopes)) {
      const requestId = randomString();
      requests[requestId] = req.query;
      // res.status(200).end();
      return res.render('login', { client, scope: req.query.scope, requestId });
    }
    // If scopes requested aren't valid then we return 401
    return res.status(401).end();
  }
  return res.status(401).end();
});

app.post('/approve', (req, res) => {
  const { userName, password, requestId } = req.body;
  if (
    users.hasOwnProperty(userName) &&
    users[userName] === password &&
    requests.hasOwnProperty(requestId)
  ) {
    const clientReq = requests[requestId];
    delete requests[requestId];

    const code = randomString();
    authorizationCodes[code] = { clientReq, userName };

    const { redirect_uri: redirectUriString, state } = clientReq;
    const redirectUrl = new URL(redirectUriString);
    redirectUrl.searchParams.append('code', code);
    redirectUrl.searchParams.append('state', state);
    return res.redirect(redirectUrl.toString());
  }
  return res.status(401).end();
});

app.post('/token', (req, res) => {
  const { authorization } = req.headers;
  if (!authorization) {
    return res.status(401).end();
  }

  const { clientId, clientSecret } = decodeAuthCredentials(authorization);
  if (clients.hasOwnProperty(clientId) && clients[clientId].clientSecret !== clientSecret) {
    return res.status(401).end();
  }

  const { code } = req.body;
  if (!code || !authorizationCodes.hasOwnProperty(code)) {
    return res.status(401).end();
  }
  const obj = authorizationCodes[code];
  delete authorizationCodes[code];

  const { userName, clientReq } = obj;
  const jwtToken = jwt.sign({ userName, scope: clientReq.scope }, config.privateKey, {
    algorithm: 'RS256',
  });
  return res.status(200).json({
    access_token: jwtToken,
    token_type: 'Bearer',
  });
});

const server = app.listen(config.port, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
});

// for testing purposes

module.exports = { app, requests, authorizationCodes, server };
