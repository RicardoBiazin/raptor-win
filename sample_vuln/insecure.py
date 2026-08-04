# Amostra PROPOSITALMENTE vulnerável — usada só pelo smoke test do CI.
# Não é código real; serve para provar que o raptor-win detecta algo.
import hashlib
import subprocess


def weak_hash(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # weak hash (esperado)


def run(user_input: str) -> None:
    subprocess.run(user_input, shell=True)  # command injection (esperado)
