# Crittografia a chiave pubblica

{{#include ../../banners/hacktricks-training.md}}

Molte challenge avanzate di crittografia nei CTF coinvolgono RSA, crittografia a curve ellittiche (ECC), ECDSA, reticoli o randomness debole.

## Tool consigliati

- [SageMath](https://www.sagemath.org/) per l'aritmetica modulare, le curve ellittiche e la riduzione dei reticoli<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) per testare le debolezze comuni di RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) per verificare se un intero ha fattori noti<sup>[[3]](#references)</sup>
- La libreria Python [`ecdsa`](https://ecdsa.readthedocs.io/) per il parsing delle chiavi, la firma e la verifica<sup>[[7]](#references)</sup>

## RSA

Inizia da qui quando una challenge fornisce `n`, `e` e `c`, oltre a un suggerimento come un modulo condiviso, un esponente basso, bit parziali della chiave o messaggi correlati.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se sono coinvolte firme, verifica la presenza di riutilizzo, bias o leak del nonce prima di presumere che sia necessario risolvere il problema del logaritmo discreto sottostante.

### Riutilizzo / bias del nonce ECDSA

ECDSA richiede un numero segreto `k` nuovo per ogni messaggio. Se lo stesso `k` firma gli hash di due messaggi diversi, la chiave privata può essere recuperata dai valori pubblici della firma.<sup>[[4]](#references)</sup>

Anche quando `k` non è identico, il bias o il leak dei bit del nonce in molte firme può consentire un recupero basato su reticoli.<sup>[[5]](#references)</sup>

Recupero tecnico quando `k` viene riutilizzato:<sup>[[4]](#references)</sup>

Equazioni della firma ECDSA (ordine del gruppo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se lo stesso `k` viene riutilizzato per due messaggi `m1, m2`, producendo le firme `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Attacchi invalid-curve

Se un protocollo non verifica che un punto di input appartenga alla curva prevista e al sottogruppo corretto, un attaccante può forzare operazioni in un gruppo più debole e recuperare informazioni su uno scalare segreto. SEC 1 specifica i controlli di validazione della chiave pubblica destinati a impedire tali input.<sup>[[6]](#references)</sup>

Nota tecnica:

- Verifica che i punti non siano il punto all'infinito, abbiano coordinate valide, soddisfino l'equazione della curva e appartengano al sottogruppo richiesto.<sup>[[6]](#references)</sup>
- Nelle challenge CTF, questo scenario viene spesso modellato come un server che moltiplica un punto scelto dall'attaccante per uno scalare segreto e restituisce un valore derivato.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard per le firme digitali](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner e Heninger: Biased Nonce Sense — attacchi basati su reticoli contro firme ECDSA deboli](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Crittografia a curve ellittiche](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentazione Python di `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
