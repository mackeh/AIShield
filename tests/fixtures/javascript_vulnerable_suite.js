const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

const secret = "hardcoded_secret";
const jwtSecret = "another-hardcoded-secret";

function insecureAuth(token, expectedToken, apiKey, expectedApiKey) {
  if (token === expectedToken) return true;
  if (apiKey === expectedApiKey) return true;
  return false;
}

function insecureCrypto(password, key, payload) {
  const weak = crypto.createHash('md5').update(password).digest('hex');
  const legacy = crypto.createHash("sha1").update(password).digest('hex');
  const cipher = crypto.createCipher('aes-256-cbc', key);
  const token = Math.random().toString(36).slice(2);
  const decoded = jwt.verify(token, jwtSecret, { ignoreExpiration: true });
  return { weak, legacy, cipher, token, decoded };
}

function insecureInjection(req, res, db, collection) {
  db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  document.body.innerHTML = req.query.html;
  eval(req.query.expr);
  exec("ls " + req.query.path);
  fs.readFile(req.query.file, () => {});
  res.redirect(req.query.next);
  collection.find({ $where: req.query.filter });
}

function insecureConfig(app, cors) {
  app.use(cors({ origin: "*" }));
  app.set('env', 'development');
  const settings = { debug: true };
  return settings;
}

module.exports = { insecureAuth, insecureCrypto, insecureInjection, insecureConfig };
