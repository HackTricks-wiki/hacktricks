# TLS et certificats

{{#include ../../banners/hacktricks-training.md}}

Cette section couvre l’inspection X.509, les encodages, les conversions et les erreurs de validation pertinentes pour la sécurité.

## Analyse X.509

OpenSSL peut afficher les champs décodés d’un certificat, tandis que `asn1parse` montre la structure ASN.1 sous-jacente.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Examinez au minimum :

- le sujet, l’émetteur et le Subject Alternative Name (SAN) ;
- l’usage de la clé et l’usage étendu de la clé ;
- les contraintes de base et les contraintes de longueur de chemin ;
- les dates de validité `notBefore` et `notAfter` ;
- les paramètres de la clé publique et l’algorithme de signature.

Les signatures obsolètes, telles que celles basées sur MD5 ou SHA-1, sont des constats particulièrement importants, même si leur acceptation et leur impact précis dépendent du validateur et du contexte de confiance.<sup>[[3]](#references)</sup>

La RFC 5280 définit le profil Internet X.509 et les règles de traitement des extensions telles que SAN, l’usage de la clé, les contraintes de nom et les contraintes de base.<sup>[[3]](#references)</sup>

## Encodages et conteneurs

- **Encodage textuel de type PEM :** données Base64 entre des délimiteurs `BEGIN` et `END`.
- **DER :** représentation binaire des Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`) :** contient généralement des certificats et une chaîne de certificats, mais pas de clés privées.
- **PKCS#12 (`.p12` ou `.pfx`) :** peut contenir des clés privées, des certificats et des certificats complémentaires.

La RFC 7468 spécifie les encodages textuels utilisés pour les structures PKIX, PKCS et CMS ; la commande `pkcs12` d’OpenSSL crée et analyse les fichiers PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Traitez `out.pem` comme une donnée sensible : sauf si des options telles que `-nokeys` sont utilisées, la sortie peut contenir des éléments de clé privée.<sup>[[5]](#references)</sup>

## Liste de vérification de l’examen de sécurité

Appliquez les exigences de traitement des certificats de la RFC 5280 lors de l’examen d’un validateur ou d’une décision de confiance.<sup>[[3]](#references)</sup>

- Vérifiez toute la chaîne jusqu’à une ancre explicitement approuvée ; ne faites pas implicitement confiance aux racines fournies par l’utilisateur.
- Vérifiez le nom d’hôte ou l’identité du service par rapport aux valeurs SAN.<sup>[[8]](#references)</sup>
- Appliquez les contraintes de base, les contraintes de nom, l’usage de la clé et l’usage étendu de la clé.
- Rejetez les certificats expirés ou pas encore valides, ainsi que les algorithmes de clé ou de signature interdits.
- Associez les identités des certificats clients au bon compte applicatif et au contexte d’autorisation correspondant.

## Journaux Certificate Transparency

Certificate Transparency fournit des journaux consultables publiquement des certificats émis.<sup>[[6]](#references)</sup> Recherchez un domaine avec crt.sh lors d’une découverte autorisée des actifs.<sup>[[7]](#references)</sup>

## References

- [1] [Documentation OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Documentation OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Profil des certificats et des CRL de l’infrastructure à clé publique Internet X.509](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Encodages textuels des structures PKIX, PKCS et CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Documentation OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Recherche de certificats](https://crt.sh/)
- [8] [RFC 9525 - Identité du service dans TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
