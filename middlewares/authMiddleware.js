const jwt = require('jsonwebtoken');
const secretKey = 'your_secret_key';

function verifyTokenAndRole(roles) {
    return (req, res, next) => {
        const token = req.headers['authorization'];

        if (!token) {
            return res.status(401).json({ message: 'Authorization token is required' });
        }

        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: 'Invalid token' });
            }

            if (!roles.includes(decoded.role)) {
                return res.status(403).json({ message: 'Unauthorized role' });
            }

            req.user = decoded;
            next();
        });
    };
}

module.exports = verifyTokenAndRole;
