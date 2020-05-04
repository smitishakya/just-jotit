const express = require('express');
// To learn more about the jsonwebtoken standard, see:
// https://jwt.io/introduction/
const jwt = require('jsonwebtoken');

const { localPassportMiddleware, jwtPassportMiddleware } = require('../auth/auth.strategy');
const { JWT_SECRET, JWT_EXPIRY } = require('../config.js');

const authRouter = express.Router();
//recieve a user then encrypts into a JSON web token that we can issue out to the user 
//so they can just quickly use this as their ID card to access protected endpoint.
function createJwtToken(user) {
    return jwt.sign({ user }, JWT_SECRET, {
        subject: user.username,
        expiresIn: JWT_EXPIRY,
        algorithm: 'HS256'
    });
}

authRouter.post('/login', localPassportMiddleware, (request, response) => {
    const user = request.user.serialize();
    const jwtToken = createJwtToken(user);
    response.json({ jwtToken, user });
});

authRouter.post('/refresh', jwtPassportMiddleware, (request, response) => {
    const user = request.user;
    const jwtToken = createJwtToken(user);
    response.json({ jwtToken, user });
});

module.exports = { authRouter };