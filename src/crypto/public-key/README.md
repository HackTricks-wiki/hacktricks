# Cryptographie à clé publique

{{#include ../../banners/hacktricks-training.md}}

De nombreux challenges avancés de cryptographie en CTF impliquent RSA, la cryptographie sur les courbes elliptiques (ECC), ECDSA, les réseaux ou un générateur aléatoire faible.

## Outils recommandés

- [SageMath](https://www.sagemath.org/) pour l’arithmétique modulaire, les courbes elliptiques et la réduction de réseau<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) pour tester les faiblesses courantes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) pour vérifier si un entier possède des facteurs connus<sup>[[3]](#references)</sup>
- La [bibliothèque Python `ecdsa`](https://ecdsa.readthedocs.io/) pour l’analyse des clés, la signature et la vérification<sup>[[7]](#references)</sup>

## RSA

Commencez ici lorsqu’un challenge fournit `n`, `e` et `c`, ainsi qu’un indice comme un module partagé, un exposant faible, des bits partiels de la clé ou des messages liés.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

En présence de signatures, recherchez une réutilisation, un biais ou une fuite du nonce avant de supposer qu’il faut résoudre le problème du logarithme discret sous-jacent.

### Réutilisation / biais du nonce ECDSA

ECDSA nécessite un nombre secret `k` unique pour chaque message. Si le même `k` signe deux condensats de message différents, la clé privée peut être retrouvée à partir des valeurs des signatures publiques.<sup>[[4]](#references)</sup>

Même si `k` n’est pas identique, un biais ou une fuite de bits du nonce sur de nombreuses signatures peut permettre une récupération par réseau.<sup>[[5]](#references)</sup>

Détails techniques de la récupération en cas de réutilisation de `k` :<sup>[[4]](#references)</sup>

Équations de signature ECDSA (ordre du groupe `n`) :

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si le même `k` est réutilisé pour deux messages `m1, m2`, produisant les signatures `(r, s1)` et `(r, s2)` :

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocole ne vérifie pas qu’un point fourni appartient à la courbe attendue et au bon sous-groupe, un attaquant peut forcer des opérations dans un groupe plus faible et récupérer des informations sur un scalaire secret. La norme SEC 1 spécifie des vérifications de validation des clés publiques destinées à empêcher de telles entrées.<sup>[[6]](#references)</sup>

Note technique :

- Vérifiez que les points ne sont pas le point à l’infini, que leurs coordonnées sont valides, qu’ils satisfont l’équation de la courbe et qu’ils appartiennent au sous-groupe requis.<sup>[[6]](#references)</sup>
- Dans les challenges CTF, ce cas est souvent modélisé par un serveur qui multiplie un point choisi par l’attaquant par un scalaire secret et renvoie une valeur dérivée.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5 : norme de signature numérique](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner et Heninger : Biased Nonce Sense — attaques par réseau contre les signatures ECDSA faibles](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0 : cryptographie sur les courbes elliptiques](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentation Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
