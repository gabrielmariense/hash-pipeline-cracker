# 🔐 Hashcracker [PT](https://github.com/gabrielmariense/hash-pipeline-cracker) | [EN](https://github.com/gabrielmariense/hash-pipeline-cracker/blob/main/README_EN.md)

Ferramenta em Python para quebra de hashes baseada em **pipelines configuráveis de encoding e hashing**.

Indicada para **pentest**, **CTFs** e **estudos de cadeias não convencionais de hash**, onde a string passa por múltiplas etapas de transformação antes do armazenamento  
(ex: `md5 → base64 → sha1`).

---

## 🧠 Conceito

O Hashcracker utiliza pipelines de transformação para reproduzir como uma senha foi processada antes do armazenamento.

Cada palavra da wordlist passa por uma sequência de hashes e encodings definida pelo usuário.
Quando um hash é aplicado logo após outro, a conversão para hexadecimal é feita automaticamente, permitindo pipelines simples como:

```
md5,sha512
```

---

## ⚙️ Funcionalidades

- Pipelines configuráveis de hash e encoding  
- Modo **interativo** e **modo direto (CLI)**  
- Conversão automática **hex implícita entre hashes**  
- Comparação final **sempre textual**  
- Processamento interno padronizado em `bytes → bytes`  

---

## 📦 Instalação

Requisitos:
- Python 3.8 ou superior

Clone o repositório e execute diretamente:

```bash
git clone <repo>
cd hashcracker
python3 hashcracker.py -h
```

---

## ▶️ Uso

### Modo interativo
```bash
python3 hashcracker.py wordlist.txt hashes.txt
```

### Modo direto
```bash
python3 hashcracker.py wordlist.txt hashes.txt -p md5,sha512
```

---

## 📄 hashes.txt

- Uma hash por linha  
- Deve conter o **texto final** que será gerado pelo pipeline  

---

## ⚠️ Aviso Legal

Ferramenta desenvolvida **exclusivamente para fins educacionais** e uso em **ambientes controlados**, como estudos, CTFs e laboratórios de pentest.

O uso em sistemas sem autorização é ilegal.  
Toda responsabilidade pelo uso indevido é do usuário.

---

## 👤 Autor

Desenvolvido por **Gabriel Mariense**, com foco em estudos de **pentest, CTFs e segurança ofensiva**.
