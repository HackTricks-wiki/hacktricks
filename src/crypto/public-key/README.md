# Crittografia a chiave pubblica

{{#include ../../banners/hacktricks-training.md}}


La maggior parte dei CTF di crittografia avanzata finisce qui: RSA, ECC/ECDSA, reticoli e scarsa casualità.

## Strumenti consigliati

- SageMath (LLL/reticoli, aritmetica modulare): https://www.sagemath.org/
- RsaCtfTool (coltellino svizzero): https://github.com/Ganapati/RsaCtfTool
- factordb (controlli rapidi dei fattori): http://factordb.com/

## RSA

Inizia da qui quando hai `n,e,c` e qualche indizio aggiuntivo (modulo condiviso, esponente basso, bit parziali, messaggi correlati).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se sono coinvolte firme, verifica prima i problemi relativi al nonce (riutilizzo/bias/leak) prima di presumere che si tratti di matematica complessa.

### Riutilizzo / bias del nonce ECDSA

Se due firme riutilizzano lo stesso nonce `k`, la chiave privata può essere recuperata.

Anche se `k` non è identico, un **bias/leakage** dei bit del nonce tra le firme può essere sufficiente per il recupero tramite reticoli (un tema comune nei CTF).

Recupero tecnico quando `k` viene riutilizzato:

Equazioni della firma ECDSA (ordine del gruppo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se lo stesso `k` viene riutilizzato per due messaggi `m1, m2` che producono le firme `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Attacchi invalid-curve

Se un protocollo non verifica che i punti appartengano alla curva prevista (o al sottogruppo), un attaccante può forzare le operazioni all'interno di un gruppo debole e recuperare i segreti.

Nota tecnica:

- Verifica che i punti appartengano alla curva e al sottogruppo corretto.
- Molti task CTF modellano questo scenario come: "il server moltiplica un punto scelto dall'attaccante per uno scalare segreto e restituisce qualcosa."

### Strumenti

- SageMath per l'aritmetica delle curve / i reticoli
- Libreria Python `ecdsa` per il parsing/la verifica

{{#include ../../banners/hacktricks-training.md}}
