# Crittografia a chiave pubblica

{{#include ../../banners/hacktricks-training.md}}

Molte challenge avanzate di crittografia nei CTF riguardano RSA, crittografia a curve ellittiche (ECC), ECDSA, reticoli o casualità debole.

## Strumenti consigliati

- [SageMath](https://www.sagemath.org/) per l'aritmetica modulare, le curve ellittiche e la riduzione dei reticoli<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) per testare le debolezze RSA più comuni<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) per verificare se un intero ha fattori noti<sup>[[3]](#references)</sup>
- La [libreria Python `ecdsa`](https://ecdsa.readthedocs.io/) per il parsing delle chiavi, la firma e la verifica<sup>[[7]](#references)</sup>

## RSA

Inizia da qui quando una challenge fornisce `n`, `e` e `c`, insieme a un indizio come un modulo condiviso, un esponente basso, bit parziali della chiave o messaggi correlati.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Se sono coinvolte firme, verifica la presenza di riutilizzo del nonce, bias o leak prima di supporre che sia necessario risolvere il problema del logaritmo discreto sottostante.

### Riutilizzo / bias del nonce ECDSA

ECDSA richiede un numero segreto `k` nuovo per ogni messaggio. Se lo stesso `k` firma gli hash di due messaggi diversi, è possibile recuperare la chiave privata dai valori pubblici delle firme.<sup>[[4]](#references)</sup>

Anche quando `k` non è identico, il bias o il leak di bit del nonce in molte firme può consentire il recupero basato su reticoli.<sup>[[5]](#references)</sup>

Dettagli tecnici sul recupero quando `k` viene riutilizzato:<sup>[[4]](#references)</sup>

Equazioni della firma ECDSA (ordine del gruppo `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Se lo stesso `k` viene riutilizzato per due messaggi `m1, m2` che producono le firme `(r, s1)` e `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Attacchi con curve non valide

Se un protocollo non verifica che un punto di input appartenga alla curva prevista e al sottogruppo corretto, un attaccante può forzare operazioni in un gruppo più debole e recuperare informazioni su uno scalare segreto. SEC 1 specifica controlli di validazione delle chiavi pubbliche pensati per impedire input di questo tipo.<sup>[[6]](#references)</sup>

Nota tecnica:

- Verifica che i punti non siano il punto all'infinito, abbiano coordinate valide, soddisfino l'equazione della curva e appartengano al sottogruppo richiesto.<sup>[[6]](#references)</sup>
- Nelle challenge CTF, questo scenario è spesso modellato come un server che moltiplica un punto scelto dall'attaccante per uno scalare segreto e restituisce un valore derivato.

## Chiavi di firma ML-DSA malformate e leak tramite campionamento con rifiuto

La chiave privata espansa di ML-DSA codifica i vettori polinomiali `s1` e `s2` con coefficienti in `[-η, η]`. FIPS 204 osserva che la decodifica di byte malformati della chiave segreta può produrre coefficienti al di fuori di questo intervallo. L'algoritmo di firma non richiede di per sé un ulteriore controllo di coerenza della chiave privata.<sup>[[8]](#references)</sup>

Il prerequisito rilevante è avere il controllo su una **chiave di firma espansa prima che venga importata o usata per firmare**, non inviare a un verificatore una chiave pubblica malformata. Un percorso di importazione permissivo potrebbe accettare coefficienti impacchettati alterati e produrre comunque firme valide. Confronta l'accettazione durante l'importazione e la firma, quindi verifica le firme risultanti usando il [workflow di fuzzing delle codifiche delle chiavi crittografiche](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

La firma calcola `z = y + c·s1` e `r0 = LowBits(w − c·s2)`, rifiutando un candidato quando `||z||∞ ≥ γ1 − β` oppure `||r0||∞ ≥ γ2 − β`. Questi controlli rendono gli output accettati indipendenti dai segreti validi di piccola entità. Coefficienti segreti fuori intervallo possono compromettere questa argomentazione sul campionamento con rifiuto e introdurre un bias dipendente dal segreto. Si tratta di un meccanismo di leak condizionale, **non** di un recupero dimostrato della chiave completa a partire dalla discrepanza segnalata nella libreria.<sup>[[8]](#references)[[10]](#references)</sup>

La validazione della chiave privata è distinta dalla verifica della firma. Nel confronto segnalato, OpenSSL, BoringSSL e SymCrypt applicavano controlli aggiuntivi sulla chiave privata, mentre liboqs accettava chiavi espanse malformate durante la firma; la libreria sottostante `mldsa-native` fornisce un validatore `pk_from_sk()` che liboqs non esponeva. FIPS 204 non impone questi controlli di validazione aggiuntivi.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard per le firme digitali](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner e Heninger: Biased Nonce Sense — attacchi basati su reticoli contro firme ECDSA deboli](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Crittografia a curve ellittiche](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentazione di Python `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Standard per le firme digitali basate su reticoli modulari](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Controlli mancanti delle chiavi ML-DSA e ML-KEM - issue #2517 di liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Stato delle implementazioni della crittografia post-quantistica](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
