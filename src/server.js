const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const fs = require('fs');
const https = require('https');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');

const app = express();
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'votre_cle_secrete',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true, httpOnly: true }
}));

app.post('/submit', async (req, res) => {
  const { nom, email, message, 'g-recaptcha-response': captcha } = req.body;
  if (!captcha) return res.status(400).send('Captcha manquant');

  const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=6LfquTYrAAAAAOEFKcYoDGEkXU9QJteXql4mN1sZ&response=${captcha}`;
  const captchaResponse = await fetch(verifyUrl, { method: 'POST' });
  const captchaResult = await captchaResponse.json();

  if (!captchaResult.success) return res.status(403).send('Captcha invalide');

  const hashedEmail = await bcrypt.hash(email, 10);
  const logEntry = `${new Date().toISOString()} - ${nom} - ${hashedEmail} - ${message}\n`;
  fs.appendFileSync(path.join(__dirname, '../logs/access.log'), logEntry);

  res.send('Formulaire envoyé avec succès.');
});

const options = {
  key: fs.readFileSync(path.join(__dirname, '../config/key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../config/cert.pem'))
};

https.createServer(options, app).listen(3000, () => {
  console.log('Serveur HTTPS démarré sur https://localhost:3000');
});
