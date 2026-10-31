# Flusso di lavoro CTF di crittografia

{{#include ../../banners/hacktricks-training.md}}

## Lista di controllo per il triage

1. Identifica cosa hai: encoding, cifratura, hash, firma o MAC.
2. Determina cosa è controllato: plaintext/ciphertext, IV/nonce, chiave, oracle (padding/errori/timing), leak parziale.
3. Classifica: simmetrica (AES/CTR/GCM), a chiave pubblica (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classica (Vigenere/XOR).
4. Applica prima i controlli con la probabilità più alta: decodifica degli strati, XOR con plaintext noto, riutilizzo del nonce, uso scorretto della modalità, comportamento dell’oracle.
5. Passa a metodi avanzati solo quando necessario: reticoli (LLL/Coppersmith), SMT/Z3, side-channel.

## Risorse online e utility

Sono utili per identificare e rimuovere strati, o quando serve una rapida conferma di un’ipotesi.

### Ricerca di hash

- Cerca l’hash di una challenge se sai che è sintetico/pubblico.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Ricerca su hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Non inviare hash di password reali o materiale riservato di una challenge a servizi di ricerca di terze parti. Se la divulgazione, i termini di servizio o le regole della competizione destano preoccupazione, preferisci un attacco offline con wordlist e regole.

### Strumenti di identificazione

- CyberChef (Magic, decodifica e conversione).<sup>[[7]](#references)</sup>
- dCode (ambiente per cifrari ed encoding).<sup>[[8]](#references)</sup>
- Boxentriq (risolutori per sostituzione).<sup>[[9]](#references)</sup>

### Piattaforme di esercitazione / riferimenti

- CryptoHack (challenge pratiche di crittografia).<sup>[[10]](#references)</sup>
- Cryptopals (classiche insidie della crittografia moderna).<sup>[[11]](#references)</sup>

### Decodifica automatizzata

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (prova molte basi e codifiche).<sup>[[13]](#references)</sup>

## Encoding e cifrari classici

### Tecnica

Molte challenge CTF di crittografia usano trasformazioni a strati: encoding base + sostituzione semplice + compressione. L’obiettivo è identificare gli strati e rimuoverli in sicurezza.

### Encoding: prova molte basi

Se sospetti un encoding a strati (base64 → base32 → …), prova:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indizi comuni:

- Base64: `A-Za-z0-9+/=` (il padding `=` è comune)
- Base32: `A-Z2-7=` (spesso con molto padding `=`)
- Ascii85/Base85: punteggiatura fitta; a volte racchiusa tra `<~ ~>`

### Sostituzione / monoalfabetica

- Risolutore di crittogrammi Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Recupero con plaintext noto di nomi di file Base32 sostituiti

Quando un nome di file offuscato usa solo `a-z2-7`, si espande a circa `ceil(8 * byte_length / 5)` caratteri dopo aver rimosso un suffisso fisso e lo stesso plaintext produce lo stesso output in file diversi, verifica l’ipotesi di **Base32 senza padding seguito da una sostituzione fissa dei simboli**. Questi indizi, da soli, non costituiscono una prova. Raccogli nomi di file prevedibili e i relativi ciphertext, mantieni le maiuscole/minuscole, codifica in Base32 ciascun plaintext e allinea i simboli posizione per posizione. Ogni simbolo plaintext ripetuto deve corrispondere allo stesso simbolo ciphertext e anche la mappatura inversa deve essere univoca. In un caso di ransomware, `ntuser.ini` e `NTUSER.DAT` hanno fornito coppie di questo tipo; ciò ha permesso di recuperare i nomi dei file, **non il contenuto dei file né le chiavi di cifratura**.<sup>[[28]](#references)</sup>

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

Se un target contiene simboli non mappati, ottieni altre coppie note oppure permuta solo le mappature dei simboli Base32 non ancora usati. Ripristina il padding fino a raggiungere un multiplo di otto caratteri, rifiuta Base32 non valido e nomi decodificati non stampabili, quindi ricodifica i candidati rimanenti e confrontali con l’intero ciphertext originale. I blocchi di ciphertext ripetuti possono fornire ulteriori ipotesi: nel caso precedente, `3gpng2wv` corrispondeva al Base32 `gaydambq`, che decodifica in cinque zeri ASCII. Un candidato stampabile, da solo, non costituisce una prova univoca.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Tool automatico di Nayuki per decifrare i cifrari di Cesare.<sup>[[15]](#references)</sup>
- Tool Atbash di Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Tool Vigenère di dCode.<sup>[[8]](#references)</sup>
- Solver Vigenère di Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Spesso compare come gruppi di 5 bit o 5 lettere:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Rune

Le rune sono spesso alfabeti di sostituzione; cerca "futhark cipher" e prova le tabelle di mappatura.

## Compressione nelle challenge

### Tecnica

La compressione compare costantemente come livello aggiuntivo (zlib/deflate/gzip/xz/zstd), a volte annidato. Se l'output sembra quasi analizzabile, ma appare come spazzatura, sospetta la compressione.

### Identificazione rapida

- `file <blob>`
- Cerca i magic byte:
  - gzip: `1f 8b`
  - zlib: comunemente `78 01`, `78 5e`, `78 9c` o `78 da` (il secondo byte dipende dai flag di compressione)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE grezzo

CyberChef include **Raw Deflate/Raw Inflate**, spesso il metodo più rapido quando il blob sembra compresso, ma `zlib` non funziona.

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

Questi compaiono spesso perché derivano da errori realistici degli sviluppatori o dall’uso scorretto di librerie comuni. Di solito l’obiettivo è riconoscerli e applicare un workflow noto di estrazione o ricostruzione.

### Fernet

Indizio tipico: due stringhe Base64 (token + chiave).

- Decoder/note: decoder Fernet di Asecuritysite.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vedi più share e viene menzionata una soglia `t`, è probabile che si tratti di Shamir.

- Ricostruttore online (solo per share CTF non sensibili).<sup>[[19]](#references)</sup>

### Formati salted di OpenSSL

A volte i CTF forniscono output di `openssl enc` (l’header spesso inizia con `Salted__`).

Strumenti per il bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Set di strumenti generale

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configurazione locale consigliata

Stack pratico per i CTF:

- Python e `pycryptodome` per primitive simmetriche e prototipazione rapida.<sup>[[25]](#references)</sup>
- SageMath per aritmetica modulare, CRT, reticoli e operazioni con RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 per challenge basate su vincoli (quando la crittografia si riduce a vincoli).<sup>[[27]](#references)</sup>

Pacchetti Python consigliati:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [ricerca hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [strumenti dCode](https://www.dcode.fr/tools-list)
- [9] [strumenti di decifrazione di Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Decifratore automatico di cifrari di Cesare](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifrario Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [risolutore Vigenère di Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decodificatore Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [ricostruttore di secret sharing Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentazione PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Rompere gli schemi di cifratura nel modo più semplice](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
