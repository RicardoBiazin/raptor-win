# Amostra PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
# Não é código real; serve para provar que o raptor-win detecta algo.
import hashlib
import subprocess


def weak_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # weak hash (esperado)


def run(user_input: str) -> None:
    subprocess.run(user_input, shell=True)  # command injection (esperado)

# XPath injection: input do usuario concatenado na consulta (esperado)
def buscar(tree, request):
    termo = request.GET.get("q")
    return tree.xpath("//user[name='" + termo + "']")

# Prompt injection: input do usuario vai direto ao prompt do LLM (esperado)
def resumir(client, request):
    texto = request.POST.get("texto")
    return client.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": texto}])
