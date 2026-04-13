const crypto = require('crypto');

// Weak hash
const hash = crypto.createHash('md5');

// DH key exchange (quantum vulnerable)
const dh = crypto.createDiffieHellman(2048);

// Weak cipher
const cipher = crypto.createCipheriv('des', key, iv);
