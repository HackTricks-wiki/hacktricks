# Attacchi RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapido

Raccogli:

- `n`, `e`, `c` (e gli eventuali ciphertext aggiuntivi)
- Eventuali relazioni tra i messaggi (stesso plaintext? modulus condiviso? plaintext strutturato?)
- Eventuali leak (valori parziali di `p/q`, bit di `d`, `dp/dq`, padding noto)

Poi prova:

- Verifica della fattorizzazione (Factordb / `sage: factor(n)` per valori non troppo grandi)
- Pattern con esponente basso (`e=3`, broadcast)
- Modulus comune / primi ripetuti
- Metodi reticolari (Coppersmith/LLL) quando qualcosa è quasi noto

## Attacchi RSA comuni

### Modulus comune

Se due ciphertext `c1, c2` cifrano lo **stesso messaggio** con lo **stesso modulus** `n`, ma con esponenti diversi `e1, e2` (e `gcd(e1,e2)=1`), puoi recuperare `m` usando l'algoritmo euclideo esteso:

`m = c1^a * c2^b mod n` dove `a*e1 + b*e2 = 1`.

Schema di esempio:

1. Calcola `(a, b) = xgcd(e1, e2)` in modo che `a*e1 + b*e2 = 1`
2. Se `a < 0`, interpreta `c1^a` come `inv(c1)^{-a} mod n` (lo stesso vale per `b`)
3. Moltiplica e riduci modulo `n`

### Primi condivisi tra i modulus

Se hai più modulus RSA dalla stessa challenge, verifica se condividono un primo:

- `gcd(n1, n2) != 1` indica un errore catastrofico nella generazione delle chiavi.

Questo si verifica spesso nei CTF con frasi come "abbiamo generato molte chiavi velocemente" o "randomness scadente".

### Modulus sparsi / short-sleeve

Alcuni generatori di interi grandi difettosi fanno trapelare direttamente la struttura nel modulus pubblico: ogni limb contiene solo un piccolo sottocampo casuale e il resto dei bit è `0`. In pratica, si manifestano come **blocchi di zeri equidistanti** in `n`, spesso allineati a limb da 32 o 128 bit.<sup>[[1]](#references)</sup>

Verifiche rapide:

- Stampa `n` in esadecimale e cerca finestre di zeri ripetute a intervalli regolari.
- Suddividi nuovamente `n` in limb (`2^32`, `2^64`, `2^128`) e controlla se ciascun limb è insolitamente piccolo.
- Controlla le chiavi SSH/TLS pubbliche con strumenti come **badkeys** se sospetti una generazione debole delle host key.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

È un problema più grave di un bias statistico: se entrambi i fattori privati `p` e `q` sono short-sleeve, il modulus potrebbe essere **facile da fattorizzare**.<sup>[[1]](#references)</sup>

### Fattorizzazione polinomiale di chiavi RSA strutturate

Per una larghezza di limb sospetta `w`, scrivi il modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Poiché la valutazione è moltiplicativa, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Se anche i fattori hanno coefficienti dei limb sparsi, allora:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Schema dell'attacco:

1. Fai un'ipotesi sulla larghezza del limb `w`.
2. Converti il modulus pubblico `n` in `f_n(x)` usando la base `2^w`.
3. Fattorizza `f_n(x)` sugli interi.
4. Valuta i fattori candidati nuovamente in `B = 2^w`.
5. Verifica quali candidati, moltiplicati tra loro, danno `n`.

Questo **non compromette RSA normale**. Funziona solo quando i fattori primi hanno coefficienti dei limb molto piccoli e altamente strutturati.<sup>[[1]](#references)</sup>

### Leak di limb traslati

I byte sparsi non sono sempre allineati all'estremità bassa di ciascun limb. Se la conversione diretta in base `2^w` produce coefficienti grandi, cerca traslazioni `i,j` tali che `2^i p` e `2^j q` diventino sparsi in quella base di limb. Il polinomio prodotto può comunque essere derivato dal modulus pubblico, fattorizzato e ricombinato per ottenere i fattori interi originali.<sup>[[1]](#references)</sup>

### Indizio di implementazione: bug RNG nella conversione da byte a limb

Un pattern pericoloso consiste nel calcolare il numero di limb da **32 bit**, allocare solo altrettanti **byte** e copiarli nell'array di limb:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This assegna a ogni limb da 32 bit solo **8 bit di entropia**, più un bit più significativo forzato nell'ultimo limb. I primi RSA risultanti possono spesso essere riconosciuti e fattorizzati usando solo la chiave pubblica.<sup>[[1]](#references)</sup>

### Modalità di errore DSA correlata

Se la stessa routine difettosa per i big integer viene riutilizzata per generare l'esponente privato DSA, la chiave pubblica `y = g^x` può rivelare uno spazio di ricerca per `x` **drasticamente ridotto e strutturato**. Una volta noto lo schema dei limb, gli attacchi al logaritmo discreto come **baby-step giant-step** possono diventare praticabili contro i parametri pubblici.<sup>[[1]](#references)</sup>

### Broadcast di Håstad / esponente basso

Se lo stesso testo in chiaro viene inviato a più destinatari con `e` piccolo (spesso `e=3`) e senza padding adeguato, puoi recuperare `m` tramite CRT e radice intera.

Condizione tecnica:

Se hai `e` testi cifrati dello stesso messaggio con moduli `n_i` coprimi a coppie:

- Usa CRT per recuperare `M = m^e` sul prodotto `N = Π n_i`
- Se `m^e < N`, allora `M` è la vera potenza intera e `m = integer_root(M, e)`

### Wiener attack: esponente privato piccolo

Se `d` è troppo piccolo, le frazioni continue possono recuperarlo da `e/n`.

### Insidie di RSA textbook

Se vedi:

- Nessun OAEP/PSS, esponenziazione modulare grezza
- Cifratura deterministica

allora gli attacchi algebrici e l'abuso degli oracle diventano molto più probabili.

### Tool

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, radici, CF): https://www.sagemath.org/

## Schemi con messaggi correlati

Se vedi due testi cifrati con lo stesso modulo e messaggi correlati algebricamente (ad es., `m2 = a*m1 + b`), cerca attacchi "related-message" come Franklin–Reiter. In genere richiedono:

- stesso modulo `n`
- stesso esponente `e`
- relazione nota tra i testi in chiaro

In pratica, spesso si risolve con Sage impostando polinomi modulo `n` e calcolando un MCD.

## Reticoli / Coppersmith

Ricorri a questo approccio quando hai bit parziali, un testo in chiaro strutturato o relazioni strette che rendono piccolo il valore sconosciuto.

I metodi reticolari (LLL/Coppersmith) si presentano ogni volta che hai informazioni parziali:

- Testo in chiaro parzialmente noto (messaggio strutturato con coda sconosciuta)
- `p`/`q` parzialmente noti (bit più significativi trapelati)
- Differenze sconosciute piccole tra valori correlati

### Cosa riconoscere

Indizi tipici nelle challenge:

- "Abbiamo fatto leak dei bit più o meno significativi di p"
- "La flag è incorporata così: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Abbiamo usato RSA ma con un piccolo padding casuale"

### Strumenti

In pratica userai Sage per LLL e un template noto per l'istanza specifica.

Punti di partenza consigliati:

- Template crittografici Sage per CTF: https://github.com/defund/coppersmith
- Riferimento di tipo survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Fattorizzare chiavi RSA "short-sleeve" con i polinomi](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Strumento standalone badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

