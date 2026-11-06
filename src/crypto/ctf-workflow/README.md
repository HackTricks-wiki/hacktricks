# Flusso di lavoro CTF Crypto

{{#include ../../banners/hacktricks-training.md}}

## Lista di controllo per il triage

1. Identifica cosa hai: encoding vs crittografia vs hash vs firma vs MAC.
2. Determina cosa è controllabile: plaintext/ciphertext, IV/nonce, chiave, oracle (padding/errore/timing), leak parziale.
3. Classifica: simmetrica (AES/CTR/GCM), a chiave pubblica (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classica (Vigenere/XOR).
4. Prova prima i controlli con la probabilità più alta: decodifica dei livelli, known-plaintext XOR, riutilizzo del nonce, uso improprio della modalità, comportamento dell’oracle.
5. Passa ai metodi avanzati solo quando necessario: reticoli (LLL/Coppersmith), SMT/Z3, side-channel.

## Risorse online e utility

Sono utili quando il compito consiste nell’identificazione e nella rimozione dei livelli, oppure quando serve una rapida conferma di un’ipotesi.

### Ricerca di hash

- Cerca un hash della challenge quando sai che è sintetico/pubblico.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Ricerca su hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Non inviare hash di password reali o materiale riservato della challenge a servizi di ricerca di terze parti. Se la divulgazione, i termini di servizio o le regole della competizione sono un problema, preferisci un attacco offline con wordlist e regole.

### Strumenti di identificazione

- CyberChef (Magic, decodifica e conversione).<sup>[[7]](#references)</sup>
- dCode (ambiente di test per cifrari/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solver per sostituzioni).<sup>[[9]](#references)</sup>

### Piattaforme di pratica / riferimenti

- CryptoHack (challenge pratiche di crittografia).<sup>[[10]](#references)</sup>
- Cryptopals (classiche insidie della crittografia moderna).<sup>[[11]](#references)</sup>

### Decodifica automatizzata

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prova molte basi/encoding).<sup>[[13]](#references)</sup>

Per il sorgente di linguaggi esoterici e lo stato di interpreti personalizzati, consulta [Crypto CTF Misc](../ctf-misc/).

## Encoding e cifrari classici

### Tecnica

Molte challenge crypto dei CTF sono trasformazioni a più livelli: encoding Base + sostituzione semplice + compressione. L’obiettivo è identificare i livelli e rimuoverli in modo sicuro.

### Encoding: prova molte basi

Se sospetti un encoding a più livelli (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indizi comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso con molto padding `=`)
- Ascii85/Base85: punteggiatura densa; a volte racchiuso tra `<~ ~>`

### Sostituzione / monoalfabetico

- Solver per crittogrammi Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Recupero con known-plaintext di nomi di file Base32 sostituiti

Quando un nome di file offuscato usa solo `a-z2-7`, dopo aver rimosso un suffisso fisso ha una lunghezza di circa `ceil(8 * byte_length / 5)` caratteri e lo stesso plaintext produce lo stesso output in file diversi, verifica l’ipotesi di **Base32 senza padding seguito da una sostituzione fissa dei simboli**. Questi indizi, da soli, non costituiscono una prova. Raccogli nomi di file prevedibili e i relativi ciphertext, mantieni le maiuscole/minuscole, codifica ogni plaintext in Base32 e allinea i simboli posizione per posizione. Ogni simbolo plaintext ripetuto deve corrispondere allo stesso simbolo ciphertext, e anche la mappatura inversa deve essere univoca. In un caso di ransomware, `ntuser.ini` e `NTUSER.DAT` hanno fornito coppie di questo tipo; ciò ha permesso di recuperare i nomi dei file, **non i contenuti dei file né le chiavi di crittografia**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Se un target contiene simboli non mappati, ottieni altre coppie note oppure permuta solo le mappature dei simboli Base32 inutilizzati. Ripristina il padding fino a raggiungere un multiplo di otto caratteri, rifiuta Base32 non valido e nomi decodificati non stampabili, quindi ricodifica i candidati rimanenti e confrontali con l’intero ciphertext originale. I blocchi di ciphertext ripetuti possono fornire ulteriori indizi: nel caso precedente, `3gpng2wv` è stato ricondotto a Base32 `gaydambq`, che decodifica in cinque zeri ASCII. Un candidato stampabile, da solo, non costituisce una prova univoca.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Strumento automatico di decifrazione del cifrario Caesar di Nayuki.<sup>[[15]](#references)</sup>
- Strumento Atbash di Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Strumento Vigenère di dCode.<sup>[[8]](#references)</sup>
- Solver Vigenère di Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Spesso si presenta come gruppi di 5 bit o 5 lettere:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Le rune sono spesso alfabeti di sostituzione; cerca "futhark cipher" e prova le tabelle di mappatura.

## Compressione nelle challenge

### Tecnica

La compressione compare spesso come livello aggiuntivo (zlib/deflate/gzip/xz/zstd), talvolta annidato. Se l’output sembra quasi interpretabile ma appare senza senso, sospetta la compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic bytes:
  - gzip: `1f 8b`
  - zlib: comunemente `78 01`, `78 5e`, `78 9c` o `78 da` (il secondo byte dipende dai flag di compressione)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE grezzo

CyberChef include **Raw Deflate/Raw Inflate**, spesso il metodo più rapido quando il blob sembra compresso ma `zlib` non funziona.

### CLI utile

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

Sono frequenti perché rappresentano errori realistici degli sviluppatori o l'uso scorretto di librerie comuni. Di solito l'obiettivo è riconoscerli e applicare un workflow noto di estrazione o ricostruzione.

### Fernet

Indizio tipico: due stringhe Base64 (token + chiave).

- Decoder/appunti: decoder Fernet di Asecuritysite.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se sono presenti più share e viene menzionata una soglia `t`, probabilmente si tratta di Shamir.

- Ricostruttore online (solo per share di CTF non sensibili).<sup>[[19]](#references)</sup>

### Formati OpenSSL con salt

A volte i CTF forniscono output di `openssl enc` (l'intestazione spesso inizia con `Salted__`).

Strumenti per il bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Set di strumenti generali

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configurazione locale consigliata

Stack pratico per i CTF:

- Python e `pycryptodome` per primitive simmetriche e prototipazione rapida.<sup>[[25]](#references)</sup>
- SageMath per aritmetica modulare, CRT, reticoli e operazioni su RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 per le sfide basate su vincoli (quando la crittografia si riduce a vincoli).<sup>[[27]](#references)</sup>

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
- [15] [Nayuki - decifratore automatico del cifrario di Cesare](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifrario Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [risolutore Vigenère Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decodificatore Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [ricostruttore della condivisione segreta di Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentazione PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Violare gli schemi di cifratura nel modo più semplice](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
