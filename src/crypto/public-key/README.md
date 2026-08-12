# Cryptographie à clé publique

{{#include ../../banners/hacktricks-training.md}}

De nombreux challenges avancés de cryptographie en CTF impliquent RSA, la cryptographie à courbe elliptique (ECC), ECDSA, les réseaux, ou une faible entropie aléatoire.

## Outils recommandés

- [SageMath](https://www.sagemath.org/) pour l'arithmétique modulaire, les courbes elliptiques et la réduction de réseaux<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) pour tester les faiblesses courantes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) pour vérifier si un entier possède des facteurs connus<sup>[[3]](#references)</sup>
- La [bibliothèque Python `ecdsa`](https://ecdsa.readthedocs.io/) pour l'analyse des clés, la signature et la vérification<sup>[[7]](#references)</sup>

## RSA

Commencez ici lorsqu'un challenge fournit `n`, `e` et `c`, avec un indice tel qu'un modulus partagé, un faible exposant, des bits de clé partiels ou des messages liés.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si des signatures sont impliquées, testez la réutilisation du nonce, le biais ou les leaks avant de supposer qu'il faut résoudre le problème sous-jacent du logarithme discret.

### ECDSA nonce reuse / bias

ECDSA nécessite un nombre secret `k` différent pour chaque message. Si le même `k` signe les hashes de deux messages différents, la clé privée peut être récupérée à partir des valeurs publiques des signatures.<sup>[[4]](#references)</sup>

Même lorsque `k` n'est pas identique, un biais ou un leak de bits du nonce sur de nombreuses signatures peut permettre une récupération fondée sur les réseaux.<sup>[[5]](#references)</sup>

Récupération technique lorsque `k` est réutilisé :<sup>[[4]](#references)</sup>

Équations de signature ECDSA (ordre du groupe `n`) :

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si le même `k` est réutilisé pour deux messages `m1, m2`, produisant les signatures `(r, s1)` et `(r, s2)` :

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocole ne vérifie pas qu'un point d'entrée appartient à la courbe attendue et au sous-groupe correct, un attaquant peut forcer des opérations dans un groupe plus faible et récupérer des informations sur un scalaire secret. SEC 1 spécifie des contrôles de validation de clé publique destinés à empêcher de telles entrées.<sup>[[6]](#references)</sup>

Note technique :

- Vérifiez que les points ne sont pas le point à l'infini, qu'ils possèdent des coordonnées valides, qu'ils satisfont l'équation de la courbe et qu'ils appartiennent au sous-groupe requis.<sup>[[6]](#references)</sup>
- Dans les challenges CTF, cela est souvent modélisé par un serveur qui multiplie un point choisi par l'attaquant par un scalaire secret et renvoie une valeur dérivée.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
