# Attacchi RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapido

Raccogli:

- `n`, `e`, `c` (e qualsiasi ciphertext aggiuntivo)
- Qualsiasi relazione tra i messaggi (stesso plaintext? modulo condiviso? plaintext strutturato?)
- Any leaks (partial `p/q`, bit di `d`, `dp/dq`, padding noto)

Poi prova:

- Controllo fattorizzazione (Factordb / `sage: factor(n)` per n relativamente piccoli)
- Pattern di basso esponente (`e=3`, broadcast)
- Modulo comune / primi ripetuti
- Metodi di lattice (Coppersmith/LLL) quando qualcosa è quasi noto

## Common RSA attacks

### Common modulus

Se due ciphertext `c1, c2` cifrano lo **stesso messaggio** sotto lo **stesso modulo** `n` ma con esponenti diversi `e1, e2` (e `gcd(e1,e2)=1`), puoi recuperare `m` usando l'algoritmo euclideo esteso:

`m = c1^a * c2^b mod n` dove `a*e1 + b*e2 = 1`.

Schema di esempio:

1. Calcola `(a, b) = xgcd(e1, e2)` così che `a*e1 + b*e2 = 1`
2. Se `a < 0`, interpreta `c1^a` come `inv(c1)^{-a} mod n` (idem per `b`)
3. Moltiplica e riduci modulo `n`

### Shared primes across moduli

Se hai più moduli RSA dallo stesso challenge, verifica se condividono un primo:

- `gcd(n1, n2) != 1` implica un fallimento catastrofico nella generazione delle chiavi.

Questo capita spesso nei CTF: "we generated many keys quickly" o "bad randomness".

### Håstad broadcast / low exponent

Se lo stesso plaintext è inviato a più destinatari con piccolo `e` (spesso `e=3`) e senza padding adeguato, puoi recuperare `m` tramite CRT e radice intera.

Condizione tecnica:

Se hai `e` ciphertext dello stesso messaggio sotto moduli a coppie coprimi `n_i`:

- Usa CRT per recuperare `M = m^e` sul prodotto `N = Π n_i`
- Se `m^e < N`, allora `M` è la vera potenza intera, e `m = integer_root(M, e)`

### Wiener attack: small private exponent

Se `d` è troppo piccolo, le frazioni continue possono recuperarlo da `e/n`.

### Textbook RSA pitfalls

Se noti:

- Nessun OAEP/PSS, sola esponenziazione modulare
- Cifratura deterministica

allora attacchi algebrici e abusione di oracle diventano molto più probabili.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Se vedi due ciphertext sotto lo stesso modulo con messaggi algebraicamente correlati (es., `m2 = a*m1 + b`), cerca attacchi "related-message" come Franklin–Reiter. Questi tipicamente richiedono:

- stesso modulo `n`
- stesso esponente `e`
- relazione nota tra i plaintext

In pratica questo si risolve spesso con Sage impostando polinomi modulo `n` e calcolando un GCD.

## Lattices / Coppersmith

Ricorri a questo quando hai bit parziali, plaintext strutturato, o relazioni ravvicinate che rendono l'incognito piccolo.

I metodi di lattice (LLL/Coppersmith) compaiono ogni volta che hai informazioni parziali:

- Plaintext parzialmente noto (messaggio strutturato con suffisso incognito)
- `p`/`q` parzialmente noti (bit alti leakati)
- Piccole differenze sconosciute tra valori correlati

### Cosa riconoscere

Indizi tipici nei challenge:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In pratica userai Sage per LLL e un template noto per l'istanza specifica.

Buoni punti di partenza:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
