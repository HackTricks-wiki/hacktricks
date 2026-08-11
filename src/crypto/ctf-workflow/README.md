# Workflow CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist di triage

1. Identifica ciò che hai: encoding, encryption, hash, signature o MAC.
2. Determina cosa è controllabile: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), leak parziale.
3. Classifica: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Applica prima i controlli con la probabilità più alta: decodifica dei layer, XOR con plaintext noto, riutilizzo del nonce, uso errato della modalità, comportamento dell'oracle.
5. Passa ai metodi avanzati solo quando necessario: reticoli (LLL/Coppersmith), SMT/Z3, side-channels.

## Risorse online e utility

Sono utili quando il task consiste nell'identificazione e nella rimozione dei layer, oppure quando serve una rapida conferma di un'ipotesi.

### Ricerca di hash

- Cerca un hash di challenge quando è noto che sia sintetico/pubblico.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Ricerca su hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Non inviare hash di password reali o materiale riservato di challenge a servizi di ricerca di terze parti. Preferisci un attacco offline con wordlist/rule quando la divulgazione, i termini di servizio o le regole della competizione rappresentano un problema.

### Strumenti di identificazione

- CyberChef (Magic, decoding e conversione).<sup>[[7]](#references)</sup>
- dCode (ambiente per cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solver per substitution).<sup>[[9]](#references)</sup>

### Piattaforme di pratica / riferimenti

- CryptoHack (challenge pratiche di crittografia).<sup>[[10]](#references)</sup>
- Cryptopals (problemi classici della crittografia moderna).<sup>[[11]](#references)</sup>

### Decoding automatico

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prova molte basi/encoding).<sup>[[13]](#references)</sup>

## Encoding e cipher classici

### Tecnica

Molti task di crypto nei CTF sono trasformazioni a più layer: base encoding + simple substitution + compression. L'obiettivo è identificare i layer e rimuoverli in modo sicuro.

### Encoding: prova molte basi

Se sospetti un encoding a più layer (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicatori comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso con molto padding `=`)
- Ascii85/Base85: punteggiatura densa; talvolta racchiuso tra `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Appare spesso come gruppi di 5 bit o 5 lettere:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Le rune sono spesso alfabeti a sostituzione; cerca "futhark cipher" e prova le tabelle di corrispondenza.

## Compressione nelle challenge

### Tecnica

La compressione compare continuamente come livello aggiuntivo (zlib/deflate/gzip/xz/zstd), a volte annidato. Se l'output viene quasi interpretato correttamente ma sembra spazzatura, sospetta una compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic bytes:
- gzip: `1f 8b`
- zlib: comunemente `78 01`, `78 5e`, `78 9c` o `78 da` (il secondo byte dipende dai flag di compressione)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef offre **Raw Deflate/Raw Inflate**, che è spesso il modo più rapido quando il blob sembra compresso ma `zlib` fallisce.

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
## Costrutti crittografici CTF comuni

### Tecnica

Questi compaiono frequentemente perché sono errori realistici degli sviluppatori o librerie comuni utilizzate in modo errato. L'obiettivo consiste solitamente nel riconoscerli e applicare un workflow noto di estrazione o ricostruzione.

### Fernet

Indizio tipico: due stringhe Base64 (token + key).

- Decoder/note: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vengono visualizzate più share e viene menzionata una soglia `t`, è probabile che si tratti di Shamir.

- Reconstructor online (solo per share CTF non sensibili).<sup>[[19]](#references)</sup>

### Formati OpenSSL con salt

A volte i CTF forniscono output di `openssl enc` (l'header inizia spesso con `Salted__`).

Helper per il bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Set di strumenti generale

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Setup locale consigliato

Stack CTF pratico:

- Python più `pycryptodome` per primitive simmetriche e prototipazione rapida.<sup>[[25]](#references)</sup>
- SageMath per aritmetica modulare, CRT, reticoli e attività con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 per challenge basate su vincoli (quando la crittografia si riduce a vincoli).<sup>[[27]](#references)</sup>

Pacchetti Python consigliati:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [ricerca di hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [strumenti dCode](https://www.dcode.fr/tools-list)
- [9] [strumenti di code-breaking di Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - strumento automatico per violare il cifrario di Cesare](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifrario Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [risolutore Vigenère di Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decoder Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [ricostruttore di secret-sharing di Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentazione di PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
