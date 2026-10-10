# TLS e certificati

{{#include ../../banners/hacktricks-training.md}}

Questa sezione tratta l’ispezione di X.509, le codifiche, le conversioni e gli errori di validazione rilevanti per la sicurezza.

## Parsing X.509

OpenSSL può mostrare i campi decodificati di un certificato, mentre `asn1parse` mostra la struttura ASN.1 sottostante.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Esaminare almeno:

- il subject, l'issuer e il Subject Alternative Name (SAN);
- key usage ed extended key usage;
- basic constraints e path-length constraints;
- gli orari di validità `notBefore` e `notAfter`;
- i parametri della chiave pubblica e l'algoritmo di firma.

Le firme legacy, come quelle dei certificati basate su MD5 o SHA-1, sono risultati particolarmente importanti, anche se l'accettazione e l'impatto esatti dipendono dal validator e dal contesto di trust.<sup>[[3]](#references)</sup>

RFC 5280 definisce il profilo Internet X.509 e le regole di elaborazione per estensioni come SAN, key usage, name constraints e basic constraints.<sup>[[3]](#references)</sup>

## Codifiche e contenitori

- **Codifica testuale in stile PEM:** dati Base64 tra delimitatori `BEGIN` ed `END`.
- **DER:** rappresentazione binaria delle Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** contiene comunemente certificati e una catena di certificati, ma non chiavi private.
- **PKCS#12 (`.p12` o `.pfx`):** può contenere chiavi private, certificati e certificati di supporto.

RFC 7468 specifica le codifiche testuali usate per le strutture PKIX, PKCS e CMS; il comando `pkcs12` di OpenSSL crea e analizza file PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Considera `out.pem` come contenuto sensibile: a meno che non vengano usate opzioni come `-nokeys`, l'output potrebbe contenere materiale relativo a chiavi private.<sup>[[5]](#references)</sup>

## Checklist di revisione della sicurezza

Applica i requisiti di elaborazione dei certificati definiti in RFC 5280 quando esamini un validatore o una decisione di attendibilità.<sup>[[3]](#references)</sup>

- Verifica l'intera catena fino a un'ancora esplicitamente attendibile; non considerare implicitamente attendibili le root fornite dall'utente.
- Verifica il nome host o l'identità del servizio confrontandoli con i valori SAN.<sup>[[8]](#references)</sup>
- Applica i vincoli di base, i vincoli sui nomi, l'uso della chiave e l'uso esteso della chiave.
- Rifiuta i certificati scaduti o non ancora validi e gli algoritmi di chiave o firma non consentiti.
- Associa le identità dei certificati client all'account applicativo e al contesto di autorizzazione corretti.

## Log di Certificate Transparency

Certificate Transparency fornisce log pubblicamente verificabili dei certificati emessi.<sup>[[6]](#references)</sup> Cerca un dominio con crt.sh durante l'individuazione autorizzata degli asset.<sup>[[7]](#references)</sup>

## References

- [1] [Documentazione di OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Documentazione di OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profilo dell'infrastruttura a chiave pubblica Internet X.509 per certificati e CRL](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Codifiche testuali delle strutture PKIX, PKCS e CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Documentazione di OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency versione 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Ricerca certificati](https://crt.sh/)
- [8] [RFC 9525 - Identità del servizio in TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
