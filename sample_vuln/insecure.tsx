// Amostra PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
// XSS: valor editável (do banco) vira href sem validar o esquema. Um
// `javascript:...` gravado ali executa no navegador do visitante.
export function Rodape({ item }: { item: { valor: string } }) {
  return <a href={item.valor} target="_blank" rel="noopener noreferrer">link</a>
}

// XSS: HTML vindo do banco entra pelo dangerouslySetInnerHTML sem sanitizar.
// O React escapa TEXTO; este prop existe justamente para não escapar.
export function Descricao({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />
}
