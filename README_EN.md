# 🔐 Hashcracker [PT](https://github.com/gabrielmariense/hash-pipeline-cracker) | [EN](https://github.com/gabrielmariense/hash-pipeline-cracker/blob/main/README_EN.md)

Python tool for hash cracking based on **configurable encoding and hashing pipelines**.

Designed for **pentesting**, **CTFs**, and **studying non-conventional hash chains**, where a string goes through multiple transformation steps before being stored  
(e.g. `md5 → base64 → sha1`).

---

## 🧠 Concept

Hashcracker uses **transformation pipelines** to reproduce how a password was processed before storage.

Each word from the wordlist is passed through a user-defined sequence of hashes and encodings.  
When a hash is applied immediately after another hash, the intermediate result is automatically converted to **hexadecimal**, allowing simple pipelines such as:

```
md5,sha512
```

without requiring the user to handle intermediate conversions explicitly.

---

## ⚙️ Features

- Configurable hash and encoding pipelines  
- **Interactive mode** for step-by-step exploration  
- **Direct CLI mode** when the pipeline is known  
- Automatic **implicit hex conversion between hashes**  
- Final comparison is **always textual**  
- Internal processing standardized as `bytes → bytes`

---

## 📦 Installation

Requirements:
- Python 3.8 or higher

Clone the repository and run directly:

```bash
git clone <repo>
cd hashcracker
python3 hashcracker.py -h
```

No external dependencies are required.

---

## ▶️ Usage

### Interactive mode

Recommended when exploring how the hash was generated.

```bash
python3 hashcracker.py wordlist.txt hashes.txt
```

### Direct mode

Use when the transformation pipeline is already known.

```bash
python3 hashcracker.py wordlist.txt hashes.txt -p md5,sha512
```

---

## 📄 hashes.txt

- One hash per line  
- Must contain the **exact final text output** that will be produced by the pipeline  

---

## ⚠️ Legal Notice

This tool was developed **exclusively for educational purposes** and for use in **controlled environments**, such as security studies, CTFs, and pentest labs.

Using this tool against systems without explicit authorization is illegal.  
The user is solely responsible for any misuse.

---

## 👤 Author

Developed by **Gabriel Mariense**, focused on studies in **pentesting, CTFs, and offensive security**, with emphasis on real-world hash and encoding chains.
