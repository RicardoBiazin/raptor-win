// Amostra PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
// XSS: valor editável (do banco) vira href sem validar o esquema. Um
// `javascript:...` gravado ali executa no navegador do visitante.
export function Rodape({ item }: { item: { valor: string } }) {
  return <a href={item.valor} target="_blank" rel="noopener noreferrer">link</a>
}
