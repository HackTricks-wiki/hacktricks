# Attacchi RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapido

Raccogli:

- `n`, `e`, `c` (e qualsiasi ciphertext aggiuntivo)
- Eventuali relazioni tra i messaggi (stesso plaintext? modulus condiviso? plaintext strutturato?)
- Eventuali leak (`p/q` parziali, bit di `d`, `dp/dq`, padding noto)

Poi prova:

- Verifica della fattorizzazione (Factordb / `sage: factor(n)` per valori relativamente piccoli)
- Pattern con esponente basso (`e=3`, broadcast)
- Modulus condiviso / primi ripetuti
- Metodi a reticolo (Coppersmith/LLL) quando qualcosa è quasi noto

## Attacchi RSA comuni

### Common modulus

Se due ciphertext `c1, c2` cifrano lo **stesso messaggio** sotto lo **stesso modulus** `n`, ma con esponenti diversi `e1, e2` (e `gcd(e1,e2)=1`), puoi recuperare `m` usando l'algoritmo euclideo esteso:

`m = c1^a * c2^b mod n` dove `a*e1 + b*e2 = 1`.

Schema dell'esempio:

1. Calcola `(a, b) = xgcd(e1, e2)` in modo che `a*e1 + b*e2 = 1`
2. Se `a < 0`, interpreta `c1^a` come `inv(c1)^{-a} mod n` (lo stesso vale per `b`)
3. Moltiplica e riduci modulo `n`

### Shared primes across moduli

Se hai più moduli RSA dalla stessa challenge, verifica se condividono un primo:

- `gcd(n1, n2) != 1` implica un errore catastrofico nella generazione delle chiavi.

Questo si verifica frequentemente nei CTF come "abbiamo generato molte chiavi rapidamente" o "cattiva casualità".

### Sparse / short-sleeve moduli

Alcuni generatori di big integer compromessi fanno trapelare direttamente la struttura nel modulus pubblico: ogni limb contiene solo un piccolo sottocampo casuale e il resto dei bit è `0`. In pratica questo appare come **blocchi di zeri regolarmente distanziati** lungo `n`, spesso allineati a limb da 32 o 128 bit.<sup>[[1]](#references)</sup>

Controlli rapidi:

- Stampa `n` in esadecimale e cerca finestre di zeri ripetute a intervalli fissi.
- Suddividi nuovamente `n` in limb (`2^32`, `2^64`, `2^128`) e verifica se ogni limb è insolitamente piccolo.
- Verifica le chiavi pubbliche SSH/TLS con strumenti come **badkeys** quando sospetti una generazione debole delle host key.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Questo è più grave di un bias statistico: se entrambi i fattori privati `p` e `q` sono short-sleeve, il modulus può diventare **facile da fattorizzare**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Per una larghezza dei limb sospetta `w`, scrivi il modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Poiché la valutazione è moltiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se anche i fattori hanno coefficienti dei limb sparsi, allora:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Schema dell'attacco:

1. Indovina la larghezza dei limb `w`.
2. Converti il modulus pubblico `n` in `f_n(x)` usando la base `2^w`.
3. Fattorizza `f_n(x)` sugli interi.
4. Valuta nuovamente i fattori candidati in `B = 2^w`.
5. Verifica quali candidati, moltiplicati, producono `n`.

Questo **non compromette il normale RSA**. Funziona solo quando i fattori primi stessi hanno coefficienti dei limb molto piccoli e altamente strutturati.<sup>[[1]](#references)</sup>

### Shifted limb leakage

I byte sparsi non sono sempre allineati all'estremità inferiore di ogni limb. Se la conversione diretta in base `2^w` produce coefficienti grandi, cerca shift `i,j` tali che `2^i p` e `2^j q` diventino sparsi in quella base dei limb. Il polinomio prodotto può comunque essere derivato dal modulus pubblico, fattorizzato e ricombinato nei fattori interi originali.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Un pattern pericoloso consiste nel calcolare il numero di **limb da 32 bit**, allocare solo quel numero di **byte** e copiarli nell'array dei limb:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Questo assegna a ogni limb da 32 bit solo **8 bit di entropia**, oltre a un bit più significativo forzato nell'ultimo limb. I primi RSA risultanti possono spesso essere riconosciuti e fattorizzati partendo dalla sola chiave pubblica.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Se la stessa routine difettosa per i big integer viene riutilizzata per la generazione dell'esponente privato DSA, la chiave pubblica `y = g^x` può esporre uno spazio di ricerca per `x` **drasticamente ridotto e strutturato**. Una volta noto il pattern dei limb, gli attacchi al discrete log, come **baby-step giant-step**, possono diventare praticabili contro i parametri pubblici.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Se lo stesso plaintext viene inviato a più destinatari con un `e` piccolo (spesso `e=3`) e senza un padding corretto, puoi recuperare `m` tramite CRT e una radice intera.

Condizione tecnica:

Se hai `e` ciphertext dello stesso messaggio con moduli a coppie coprimi `n_i`:

- Usa CRT per recuperare `M = m^e` sul prodotto `N = Π n_i`
- Se `m^e < N`, allora `M` è la potenza intera effettiva e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` è troppo piccolo, le frazioni continue possono recuperarlo da `e/n`.

### Problemi di Textbook RSA

Se vedi:

- Nessun OAEP/PSS, raw modular exponentiation
- Cifratura deterministica

allora gli attacchi algebrici e l'abuso degli oracle diventano molto più probabili.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Pattern di messaggi correlati

Se vedi due ciphertext sotto lo stesso modulo con messaggi correlati algebricamente (ad esempio `m2 = a*m1 + b`), cerca attacchi "related-message" come Franklin–Reiter. In genere richiedono:

- stesso modulo `n`
- stesso esponente `e`
- relazione nota tra i plaintext

In pratica, questo viene spesso risolto con Sage impostando polinomi modulo `n` e calcolando un GCD.

## Lattices / Coppersmith

Ricorri a questo quando hai bit parziali, plaintext strutturati o relazioni strette che rendono piccolo il valore sconosciuto.

I metodi basati su lattice (LLL/Coppersmith) compaiono ogni volta che hai informazioni parziali:

- Plaintext parzialmente noto (messaggio strutturato con coda sconosciuta)
- `p`/`q` parzialmente noti (bit più significativi esposti)
- Differenze sconosciute piccole tra valori correlati

### Cosa riconoscere

Indizi tipici nelle challenge:

- "Abbiamo esposto i bit più significativi/più bassi di p"
- "La flag è incorporata così: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Abbiamo usato RSA con un piccolo padding casuale"

### Tooling

In pratica userai Sage per LLL e un template noto per l'istanza specifica.

Buoni punti di partenza:

- Template di crittografia Sage per CTF: https://github.com/defund/coppersmith
- Un riferimento in stile survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Fattorizzare chiavi RSA "short-sleeve" con i polinomi](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [strumento standalone badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
