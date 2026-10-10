# Workflow CTF di crittografia

{{#include ../../banners/hacktricks-training.md}}

## Checklist di triage

1. Identifica cosa hai: encoding, cifratura, hash, firma o MAC.
2. Determina cosa è controllato: plaintext/ciphertext, IV/nonce, chiave, oracle (padding/errori/timing), leak parziale.
3. Classifica: simmetrica (AES/CTR/GCM), a chiave pubblica (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classica (Vigenere/XOR).
4. Applica prima i controlli con la maggiore probabilità di successo: decodifica dei livelli, XOR con plaintext noto, riutilizzo del nonce, uso improprio della modalità, comportamento dell'oracle.
5. Passa ai metodi avanzati solo se necessario: reticoli (LLL/Coppersmith), SMT/Z3, side-channel.

## Risorse online e utilità

Sono utili quando il compito consiste nell'identificazione e nella rimozione dei livelli, o quando serve verificare rapidamente un'ipotesi.

### Ricerca di hash

- Cerca l'hash di una challenge se sai che è sintetico/pubblico.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Ricerca su hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Non inviare hash di password reali o materiale riservato di una challenge a servizi di ricerca di terze parti. Se la divulgazione, i termini di servizio o le regole della competizione sono motivo di preoccupazione, preferisci un attacco offline con wordlist e regole.

### Strumenti per l'identificazione

- CyberChef (Magic, decodifica e conversione).<sup>[[7]](#references)</sup>
- dCode (strumento per cifrari/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solver per sostituzioni).<sup>[[9]](#references)</sup>

### Piattaforme di pratica / riferimenti

- CryptoHack (challenge di crittografia pratiche).<sup>[[10]](#references)</sup>
- Cryptopals (classiche insidie della crittografia moderna).<sup>[[11]](#references)</sup>

### Decodifica automatizzata

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prova numerose basi/encoding).<sup>[[13]](#references)</sup>

## Encoding e cifrari classici

### Tecnica

Molte challenge CTF di crittografia sono trasformazioni a più livelli: encoding in base + sostituzione semplice + compressione. L'obiettivo è identificare i livelli e rimuoverli in modo sicuro.

### Encoding: prova molte basi

Se sospetti un encoding a più livelli (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indizi comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso con molto padding `=`)
- Ascii85/Base85: punteggiatura densa; a volte racchiuso tra `<~ ~>`

### Sostituzione / monoalfabetico

- Solver di crittogrammi Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Decifratore automatico di cifrari Caesar di Nayuki.<sup>[[15]](#references)</sup>
- Strumento Atbash di Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Strumento Vigenère di dCode.<sup>[[8]](#references)</sup>
- Solver Vigenère di Guballa.<sup>[[17]](#references)</sup>

### Cifrario di Bacon

Spesso appare come gruppi di 5 bit o 5 lettere:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Rune

Le rune sono spesso alfabeti di sostituzione; cerca "futhark cipher" e prova le tabelle di corrispondenza.

## Compressione nelle challenge

### Tecnica

La compressione compare continuamente come livello aggiuntivo (zlib/deflate/gzip/xz/zstd), a volte annidato. Se l'output sembra quasi analizzabile ma appare come spazzatura, sospetta la compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic byte:
  - gzip: `1f 8b`
  - zlib: comunemente `78 01`, `78 5e`, `78 9c` o `78 da` (il secondo byte dipende dai flag di compressione)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ha **Raw Deflate/Raw Inflate**, spesso il modo più rapido quando il blob sembra compresso ma `zlib` fallisce.

### CLI utili

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## Costrutti crittografici comuni nei CTF

### Tecnica

Questi compaiono spesso perché sono errori realistici degli sviluppatori o librerie comuni usate in modo errato. Di solito l'obiettivo è riconoscerli e applicare un workflow noto di estrazione o ricostruzione.

### Fernet

Indizio tipico: due stringhe Base64 (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vedi più share e viene menzionata una soglia `t`, probabilmente si tratta di Shamir.

- Ricostruttore online (solo per share CTF non sensibili).<sup>[[19]](#references)</sup>

### Formati OpenSSL con salt

A volte i CTF forniscono output di `openssl enc` (l'header spesso inizia con `Salted__`).

Strumenti per il bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Set di strumenti generali

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configurazione locale consigliata

Stack pratico per i CTF:

- Python con `pycryptodome` per primitive simmetriche e prototipazione rapida.<sup>[[25]](#references)</sup>
- SageMath per aritmetica modulare, CRT, reticoli e operazioni con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 per challenge basate su vincoli (quando la crittografia si riduce a vincoli).<sup>[[27]](#references)</sup>

Pacchetti Python consigliati:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [ricerca su hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [strumenti dCode](https://www.dcode.fr/tools-list)
- [9] [strumenti di decifrazione dei codici Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - decifratore automatico del Caesar cipher](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cipher Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [risolutore Vigenère di Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decoder Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [ricostruttore della condivisione segreta di Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentazione di PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
