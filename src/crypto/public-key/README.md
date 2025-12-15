# Crittografia a chiave pubblica

{{#include ../../banners/hacktricks-training.md}}

La maggior parte della crypto difficile nei CTF finisce qui: RSA, ECC/ECDSA, lattices e scarsa entropia.

## Strumenti consigliati

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

Inizia da qui quando hai `n,e,c` e qualche indizio extra (modulo condiviso, esponente basso, bit parziali, messaggi correlati).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se sono coinvolte firme, testa prima problemi di nonce (reuse/bias/leaks) prima di assumere che sia matematica difficile.

### ECDSA nonce reuse / bias

Se due firme riutilizzano lo stesso nonce `k`, la chiave privata può essere recuperata.

Anche se `k` non è identico, **bias/leakage** dei bit del nonce tra le firme può essere sufficiente per il recupero tramite lattice (tema comune nei CTF).

Recupero tecnico quando `k` è riutilizzato:

Equazioni della firma ECDSA (ordine del gruppo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se lo stesso `k` è riutilizzato per due messaggi `m1, m2` producendo firme `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Se un protocollo non verifica che i punti siano sulla curva attesa (o nel sottogruppo corretto), un attaccante può forzare operazioni in un gruppo debole e recuperare segreti.

Nota tecnica:

- Verificare che i punti siano sulla curva e nel sottogruppo corretto.
- Molti task CTF modellano questo come "server multiplies attacker-chosen point by secret scalar and returns something."

### Tooling

- SageMath per l'aritmetica delle curve / lattices
- `ecdsa` Python library per parsing/verifica

{{#include ../../banners/hacktricks-training.md}}
