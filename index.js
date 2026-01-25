const express = require('express');
const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Server is running!</h1>
    <ul>
      <li><a href="/hello?name=Alex">/hello?name=Alex</a></li>
      <li><a href="/hello">/hello (missing name)</a></li>
      <li><a href="/sum?a=5&b=3">/sum?a=5&b=3</a></li>
      <li><a href="/sum?a=5">/sum?a=5 (missing b)</a></li>
      <li><a href="/user/123">/user/123</a></li>
      <li><a href="/status">/status</a></li>
      <li><a href="/unknown">/unknown (404 test)</a></li>
    </ul>
  `);
});

app.get('/hello', (req, res) => {
  const name = req.query.name;
  if (!name) {
    return res.status(400).json({ error: "Missing 'name' query parameter" });
  }
  res.json({ message: `Hello, ${name}` });
});

app.get('/sum', (req, res) => {
  const a = parseFloat(req.query.a);
  const b = parseFloat(req.query.b);

  if (isNaN(a) || isNaN(b)) {
    return res.status(400).json({ error: "Both 'a' and 'b' must be valid numbers" });
  }

  res.json({ sum: a + b });
});

app.get('/user/:id', (req, res) => {
  const id = req.params.id;
  res.json({ id: id, role: 'user' });
});

app.get('/status', (req, res) => {
  res.json({
    status: 'Server is running',
    time: new Date().toISOString()
  });
});

app.use((req, res) => {
  res.status(404).send('404 - Page not found');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
