const winston = require('winston');
const logger = winston.createLogger({
    transports: [new winston.transports.File({ filename: 'security.log' })]
});

const VALID_API_KEYS = [process.env.API_KEY || 'dhc-1014-saim-key-2025'];

function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !VALID_API_KEYS.includes(apiKey)) {
        logger.warn(`Invalid API key from IP: ${req.ip}`);
        return res.status(401).send('Invalid or missing API key');
    }
    next();
}

module.exports = checkApiKey;