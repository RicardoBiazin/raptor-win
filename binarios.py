"""Binários versionados no git, identificados pelos bytes, não pela extensão.

Executável, instalador ou pacote comitado não passa por revisão de código: o
diff mostra "Binary files differ" e ninguém sabe o que entrou. É a checagem
"Binary-Artifacts" do OpenSSF Scorecard. Assinaturas escritas aqui a partir
dos formatos (fatos), sem código nem base de terceiros.

Só olha arquivos RASTREADOS (`git ls-files`): o .exe gerado pelo build e
ignorado pelo .gitignore não é problema de repositório. Pasta sem git fica de
fora — sem como saber o que é versionado, acusar seria chute.
"""

from __future__ import annotations

import mmap
import struct
import subprocess
from pathlib import Path

LIMITE_BYTES = 200 * 1024 * 1024
# Marcadores de instalador ficam no overlay (fim do arquivo), não no cabeçalho.
_INSTALADORES = ((b"Inno Setup Setup Data", "Inno Setup"),
                 (b"NullsoftInst", "NSIS"),
                 (b"7z\xbc\xaf\x27\x1c", "7-Zip SFX"))
_EMPACOTADORES = ((b"UPX0", "UPX"), (b"UPX!", "UPX"), (b".MPRESS1", "MPRESS"),
                  (b".aspack", "ASPack"), (b".themida", "Themida"))
# Wrappers que o próprio Gradle/Maven manda versionar: aviso, não problema.
_WRAPPERS = {"gradle-wrapper.jar", "maven-wrapper.jar"}
# Formatos de escritório são zip/CFBF por dentro, mas são documento.
_DOCUMENTOS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
               ".doc", ".xls", ".ppt", ".vsdx", ".xmind", ".sketch", ".fig"}


def _tipo(cab: bytes, ext: str) -> tuple[str, str] | None:
    """(classe, formato). classe: exe | arquivo. None = não é binário de interesse."""
    if cab[:2] == b"MZ" and len(cab) >= 0x40:
        pe = struct.unpack_from("<I", cab, 0x3C)[0]
        if pe + 4 <= len(cab) and cab[pe:pe + 4] == b"PE\0\0":
            return "exe", "PE (Windows)"
    if cab[:4] == b"\x7fELF":
        return "exe", "ELF (Linux)"
    if cab[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                   b"\xcf\xfa\xed\xfe"):
        return "exe", "Mach-O (macOS)"
    if cab[:4] == b"\xca\xfe\xba\xbe":
        return "exe", "classe Java" if ext == ".class" else "Mach-O universal (macOS)"
    if cab[:4] == b"\0asm":
        return "exe", "WebAssembly"
    if ext == ".pyc":
        return "exe", "bytecode Python"
    if cab[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and ext in (".msi", ".msp", ".msm"):
        return "exe", "instalador MSI"
    if ext in _DOCUMENTOS:
        return None
    if cab[:4] == b"PK\x03\x04":
        if ext in (".jar", ".war", ".ear", ".apk", ".aab", ".nupkg", ".whl", ".vsix", ".xpi",
                   ".crx"):
            return "exe", f"pacote {ext}"
        return "arquivo", "zip"
    for magica, nome in ((b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
                         (b"\x1f\x8b", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"MSCF", "cab"),
                         (b"BZh", "bzip2")):
        if cab.startswith(magica):
            return "arquivo", nome
    return None


def _marcador(arq: Path, cab: bytes) -> str | None:
    for marca, nome in _EMPACOTADORES:
        if marca in cab:
            return f"empacotado com {nome}"
    try:
        with arq.open("rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as m:
            for marca, nome in _INSTALADORES:
                # O 7z no começo é arquivo 7z comum; SFX é o 7z DEPOIS do executável.
                if m.find(marca, 1) != -1:
                    return f"instalador {nome}"
    except (OSError, ValueError):
        return None
    return None


def rastreados(raiz: Path) -> list[Path] | None:
    try:
        out = subprocess.run(["git", "-C", str(raiz), "ls-files", "-z"],
                             capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return [raiz / n for n in out.stdout.decode("utf-8", "replace").split("\0") if n]


def escanear(alvos: list[Path], skip_dirs: set[str]) -> list[dict]:
    achados = []
    for alvo in alvos:
        raiz = alvo if alvo.is_dir() else alvo.parent
        for arq in rastreados(raiz) or []:
            if any(x in skip_dirs for x in arq.parts):
                continue
            try:
                tam = arq.stat().st_size
                if not tam or tam > LIMITE_BYTES:
                    continue
                with arq.open("rb") as fh:
                    cab = fh.read(4096)
            except OSError:
                continue
            ext = arq.suffix.lower()
            tipo = _tipo(cab, ext)
            if not tipo:
                continue
            classe, formato = tipo
            try:
                rel = str(arq.relative_to(Path.cwd())).replace("\\", "/")
            except ValueError:
                rel = str(arq).replace("\\", "/")
            kb = f"{tam / 1024:.0f} KB"
            if arq.name in _WRAPPERS:
                regra, sev = "supply.wrapper-versionado", "INFO"
                msg = (f"{formato} do wrapper de build ({kb}). É versionado por desenho; confira "
                       f"o checksum com `distributionSha256Sum`/`wrapperSha256Sum`.")
            elif classe == "exe":
                marca = _marcador(arq, cab) if formato.startswith(("PE", "instalador")) else None
                if marca:
                    regra, sev = "supply.executavel-empacotado", "HIGH"
                    msg = (f"Executável {formato}, {marca}, versionado no repositório ({kb}). "
                           f"Empacotamento esconde o conteúdo até de antivírus; ninguém revisa "
                           f"o que está dentro. Publique como release, gerado pelo CI.")
                else:
                    regra, sev = "supply.binario-versionado", "MEDIUM"
                    msg = (f"Executável {formato} versionado no repositório ({kb}). Binário não "
                           f"passa por revisão (o diff só diz 'Binary files differ'). Gere no "
                           f"build ou publique como release, e tire do git.")
            else:
                regra, sev = "supply.compactado-versionado", "LOW"
                msg = (f"Arquivo compactado ({formato}) versionado ({kb}): o conteúdo não aparece "
                       f"em revisão nem na varredura. Confira o que há dentro.")
            achados.append({"rule": regra, "severity": sev, "path": rel, "line": 1,
                            "message": msg, "context": "", "evidencia": "confirmado"})
    return achados
