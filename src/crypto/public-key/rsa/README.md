# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Raccogli:

- `n`, `e`, `c` (e qualsiasi ciphertext aggiuntivo)
- Qualsiasi relazione tra i messaggi (stesso plaintext? shared modulus? structured plaintext?)
- Qualsiasi leak (partial `p/q`, bits di `d`, `dp/dq`, known padding)

Poi prova:

- Verifica di factorization (Factordb / `sage: factor(n)` per valori piccoli)
- Pattern a basso exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Metodi lattice (Coppersmith/LLL) quando qualcosa è quasi noto

## Common RSA attacks

### Common modulus

Se due ciphertext `c1, c2` cifrano lo **stesso messaggio** sotto lo **stesso modulus** `n` ma con exponent diversi `e1, e2` (e `gcd(e1,e2)=1`), puoi recuperare `m` usando l'algoritmo euclideo esteso:

`m = c1^a * c2^b mod n` dove `a*e1 + b*e2 = 1`.

Schema di esempio:

1. Calcola `(a, b) = xgcd(e1, e2)` così `a*e1 + b*e2 = 1`
2. Se `a < 0`, interpreta `c1^a` come `inv(c1)^{-a} mod n` (vale lo stesso per `b`)
3. Moltiplica e riduci modulo `n`

### Shared primes across moduli

Se hai più moduli RSA dalla stessa challenge, controlla se condividono un prime:

- `gcd(n1, n2) != 1` implica un fallimento catastrofico della key-generation.

Questo compare spesso nei CTF come "abbiamo generato molte key rapidamente" o "bad randomness".

### Sparse / short-sleeve moduli

Alcuni generatori di big-integer rotti inseriscono direttamente struttura nel public modulus: ogni limb contiene solo un piccolo sottocampo random e il resto dei bit è `0`. In pratica questo appare come **blocchi di zeri regolarmente spaziati** in `n`, spesso allineati a limb da 32-bit o 128-bit.

Controlli rapidi:

- Dump di `n` in hex e cerca finestre di zeri ripetute con passo fisso.
- Rislice `n` come limb (`2^32`, `2^64`, `2^128`) e verifica se ogni limb è insolitamente piccolo.
- Analizza le public SSH/TLS key con tool come **badkeys** quando sospetti una weak host-key generation.

Questo è più grave di un bias statistico: se entrambi i private factor `p` e `q` sono short-sleeved, il modulus può diventare **facile da fattorizzare**.

### Polynomial factorization of structured RSA keys

Per una suspected limb width `w`, scrivi il modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Poiché la valutazione è moltiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se anche i factor hanno coefficienti di limb sparsi, allora:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Schema di attacco:

1. Indovina la limb width `w`.
2. Converti il public modulus `n` in `f_n(x)` usando base `2^w`.
3. Fattorizza `f_n(x)` sugli interi.
4. Valuta i candidate factor di nuovo a `B = 2^w`.
5. Verifica quali candidate si moltiplicano per `n`.

Questo **non rompe il normal RSA**. Funziona solo quando i prime factor stessi hanno coefficienti di limb molto piccoli e altamente strutturati.

### Shifted limb leakage

I byte sparsi non sono sempre allineati all'estremità bassa di ogni limb. Se la conversione diretta in base `2^w` produce coefficienti grandi, cerca shift `i,j` tali che `2^i p` e `2^j q` diventino sparsi in quella base di limb. Il product polynomial può comunque essere derivato dal public modulus, fattorizzato e ricombinato nei factor interi originali.

### Implementation smell: byte-to-limb RNG bug

Un pattern pericoloso è calcolare il numero di **limb da 32-bit**, allocare solo quel numero di **byte**, e copiarli nell'array dei limb:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Questo fornisce a ciascun limb da 32 bit solo **8 bit di entropia** più un bit alto forzato nell'ultimo limb. Le prime RSA risultanti possono spesso essere riconosciute e fattorizzate solo dalla public key.

### Related DSA failure mode

Se la stessa routine big-integer difettosa viene riutilizzata per la generazione dell'esponente privato DSA, la public key `y = g^x` può rivelare uno spazio di ricerca **drasticamente ridotto e strutturato** per `x`. Una volta noto il pattern dei limb, attacchi discrete-log come **baby-step giant-step** possono diventare praticabili contro i parametri public.

### Håstad broadcast / low exponent

Se lo stesso plaintext viene inviato a più destinatari con `e` piccolo (spesso `e=3`) e senza padding corretto, puoi recuperare `m` tramite CRT e radice intera.

Condizione tecnica:

Se hai `e` ciphertext dello stesso messaggio sotto moduli coprimi a coppie `n_i`:

- Usa CRT per recuperare `M = m^e` sul prodotto `N = Π n_i`
- Se `m^e < N`, allora `M` è la vera potenza intera, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` è troppo piccolo, le frazioni continue possono recuperarlo da `e/n`.

### Textbook RSA pitfalls

Se vedi:

- Nessun OAEP/PSS, raw modular exponentiation
- Deterministic encryption

allora gli attacchi algebrici e l'abuso di oracle diventano molto più probabili.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Se vedi due ciphertext sotto lo stesso modulo con messaggi che sono algebricamente correlati (ad es. `m2 = a*m1 + b`), cerca attacchi "related-message" come Franklin–Reiter. In genere richiedono:

- stesso modulo `n`
- stesso esponente `e`
- relazione nota tra i plaintext

In pratica questo si risolve spesso con Sage impostando polinomi modulo `n` e calcolando un GCD.

## Lattices / Coppersmith

Usalo quando hai bit parziali, plaintext strutturato o relazioni vicine che rendono l'ignoto piccolo.

I metodi lattice (LLL/Coppersmith) compaiono ogni volta che hai informazioni parziali:

- Plaintext parzialmente noto (messaggio strutturato con coda ignota)
- `p`/`q` parzialmente noti (bit alti leakati)
- Piccole differenze ignote tra valori correlati

### Cosa riconoscere

Indizi tipici nelle challenge:

- "Abbiamo leakato i bit alti/bassi di p"
- "La flag è incorporata così: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Abbiamo usato RSA ma con un piccolo padding casuale"

### Tooling

In pratica userai Sage per LLL e un template noto per l'istanza specifica.

Buoni punti di partenza:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Un riferimento in stile survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
