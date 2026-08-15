// Amostra PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
const express = require('express')
const app = express()

app.get('/proxy', (req, res) => {
  // SSRF: URL controlada pelo cliente vai direto para um fetch (esperado)
  fetch(req.query.url).then(r => r.text()).then(t => res.send(t))
})

// SSRF de Web Push: o endpoint da inscrição vem do navegador do assinante e vai
// direto para o fetch, sem allowlist de host (esperado por raptor.ssrf.web-push-endpoint)
async function enviarPush(sub) {
  await fetch(sub.endpoint, { method: 'POST', headers: { TTL: '60' } })
}

module.exports = { app, enviarPush }
