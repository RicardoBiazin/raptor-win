// Fixture PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
const express = require('express')
const app = express()

app.get('/proxy', (req, res) => {
  // SSRF: URL controlada pelo cliente vai direto para um fetch (esperado)
  fetch(req.query.url).then(r => r.text()).then(t => res.send(t))
})

module.exports = app
