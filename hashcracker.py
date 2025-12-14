#!/usr/bin/env python3
import argparse
import base64
import hashlib
import sys
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

# ======================================================================================
# - Todas as transformações operam em bytes (bytes -> bytes).
# - Funções de hash retornam digest binário.
# - Encodings textuais (hex/base64/base32/base85/url) são etapas explícitas.
# - Não existe pipeline padrão: o usuário constrói a cadeia passo a passo.
# - Comparação com hashes.txt é sempre textual:
#     - se o pipeline termina em etapa textual, compara o texto gerado
#     - senão, converte o digest final para hex e compara
#
# Regra extra (UX):
# - Se um hash for aplicado logo após outro hash, o digest anterior é convertido
#   automaticamente para hex (bytes) antes do próximo hash.
#   Ex: md5,sha512 => md5(digest) -> hex(bytes) -> sha512(digest)
# ======================================================================================


# -------------------------
# Funções de Hash (digest binário)
# -------------------------
def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# -------------------------
# Etapas de Encode / Transformação
# -------------------------
def b64(data: bytes) -> bytes:
    return base64.b64encode(data)

def b32(data: bytes) -> bytes:
    return base64.b32encode(data)

def b85(data: bytes) -> bytes:
    return base64.b85encode(data)

def hex_encode(data: bytes) -> bytes:
    return data.hex().encode()

def url_encode(data: bytes) -> bytes:
    return urllib.parse.quote_from_bytes(data).encode()

def identity(data: bytes) -> bytes:
    return data


# -------------------------
# Etapas disponíveis para o pipeline
# -------------------------
STEPS: Dict[str, Callable[[bytes], bytes]] = {
    # hashes
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "sha512": sha512,

    # encodes / transforms
    "b64": b64,
    "b32": b32,
    "b85": b85,
    "hex": hex_encode,
    "url": url_encode,
    "id": identity,
}

HASH_STEPS = {"md5", "sha1", "sha256", "sha512"}
TEXT_STEPS = {"hex", "b64", "b32", "b85", "url"}


def list_steps() -> str:
    ordered = ["md5", "sha1", "sha256", "sha512", "hex", "b64", "b32", "b85", "url", "id"]
    return ", ".join(ordered)


# -------------------------
# Carregamento dos alvos
# -------------------------
def load_targets(path: str) -> set[str]:
    targets: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                targets.add(s)
    return targets


# -------------------------
# Execução do pipeline (com hex implícito entre hashes)
# -------------------------
def apply_pipeline(data: bytes, pipeline: List[str]) -> bytes:
    prev_was_hash = False

    for step in pipeline:
        if step in HASH_STEPS and prev_was_hash:
            data = data.hex().encode()

        data = STEPS[step](data)
        prev_was_hash = (step in HASH_STEPS)

    return data


def render_final_output(data: bytes, pipeline: List[str]) -> str:
    if pipeline and pipeline[-1] in TEXT_STEPS:
        return data.decode("utf-8", errors="ignore")
    return data.hex()


# -------------------------
# Impressão padronizada (mesmo formato do interativo)
# -------------------------
def print_match(senha: str, out: str) -> None:
    print("\n[+] MATCH ENCONTRADO")
    print(f"    Senha: {senha}")
    print(f"    Resultado: {out}")


# -------------------------
# Processo de quebra (wordlist x pipeline)
# -------------------------
def crack_once(
    wordlist_path: str,
    targets: set[str],
    pipeline: List[str],
    quiet: bool = False,
    progress_every: int = 200000,
) -> Optional[Tuple[str, str]]:
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                word = line.strip()
                if not word:
                    continue

                result_bytes = apply_pipeline(word.encode(), pipeline)
                result_text = render_final_output(result_bytes, pipeline)

                if result_text in targets:
                    return word, result_text

                if not quiet and i % progress_every == 0:
                    print(
                        f"[*] {i} tentativas... (pipeline: {' → '.join(pipeline) if pipeline else '(vazio)'})",
                        file=sys.stderr,
                    )
    except FileNotFoundError:
        print(f"[-] Wordlist não encontrada: {wordlist_path}", file=sys.stderr)
        return None

    return None


# -------------------------
# Modo interativo
# -------------------------
def interactive_loop(wordlist: str, hashes_file: str, quiet: bool) -> int:
    targets = load_targets(hashes_file)
    if not targets:
        print("[-] hashes.txt está vazio.", file=sys.stderr)
        return 1

    pipeline: List[str] = []

    print("\n[+] Modo interativo")
    print(f"[+] Etapas disponíveis: {list_steps()}")
    print("[+] Comandos: add <etapa> | undo | show | run | help | quit\n")

    while True:
        cmd = input("hashcracker> ").strip()
        if not cmd:
            continue

        low = cmd.lower()

        if low in ("quit", "exit", "q"):
            print("[*] Saindo.")
            return 0

        if low == "help":
            print("\nComandos:")
            print("  add <etapa>   adiciona uma etapa ao pipeline")
            print("  undo          remove a última etapa")
            print("  show          mostra o pipeline atual")
            print("  run           executa a quebra com o pipeline atual")
            print("  quit          encerra\n")
            print(f"Etapas disponíveis: {list_steps()}\n")
            continue

        if low == "show":
            print(f"Pipeline atual: {' → '.join(pipeline) if pipeline else '(vazio)'}")
            continue

        if low == "undo":
            if pipeline:
                print(f"[ok] removida: {pipeline.pop()}")
            else:
                print("[-] pipeline já está vazio")
            continue

        if low.startswith("add "):
            step = low.split(maxsplit=1)[1].strip()
            if step not in STEPS:
                print(f"[-] etapa inválida: {step}. Opções: {list_steps()}")
                continue
            pipeline.append(step)
            print(f"[ok] adicionada: {step}\n")  # <-- pula uma linha extra
            continue

        if low == "run":
            if not pipeline:
                print("[-] pipeline vazio. Use `add <etapa>` para montar a cadeia.")
                continue

            print(f"[*] Executando pipeline: {' → '.join(pipeline)}")
            hit = crack_once(wordlist, targets, pipeline, quiet)
            if hit:
                senha, out = hit
                print_match(senha, out)
                return 0

            print("[-] Nenhuma correspondência encontrada.")
            continue

        print("[-] comando inválido. Use: add <etapa> | undo | show | run | help | quit")


# -------------------------
# CLI
# -------------------------
def parse_pipeline_arg(p: str) -> List[str]:
    steps = [s.strip().lower() for s in p.split(",") if s.strip()]
    invalid = [s for s in steps if s not in STEPS]
    if invalid:
        raise ValueError(f"Etapas inválidas: {', '.join(invalid)}. Opções: {list_steps()}")
    return steps


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="hashcracker.py",
        description="Hashcracker baseado em pipelines de transformação (comparação textual).",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("wordlist", help="Caminho da wordlist")
    ap.add_argument("hashes", help="Arquivo hashes.txt (um alvo por linha)")
    ap.add_argument("--quiet", action="store_true", help="Menos logs")
    ap.add_argument(
        "-p",
        "--pipeline",
        help="Executa em modo direto com pipeline (ex: md5,sha512 ou md5,hex,sha512,hex)",
    )
    args = ap.parse_args()

    targets = load_targets(args.hashes)
    if not targets:
        print("[-] hashes.txt está vazio.", file=sys.stderr)
        return 1

    # Modo direto
    if args.pipeline:
        pipeline = parse_pipeline_arg(args.pipeline)
        print(f"[*] Modo direto: {' → '.join(pipeline)}")
        hit = crack_once(args.wordlist, targets, pipeline, args.quiet)
        if hit:
            senha, out = hit
            print_match(senha, out)  # <-- mesmo formato do interativo
            return 0
        print("[-] Nenhuma correspondência encontrada.")
        return 1

    # Modo interativo
    return interactive_loop(args.wordlist, args.hashes, args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
