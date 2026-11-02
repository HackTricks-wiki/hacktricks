# Cryptographie à clé publique

{{#include ../../banners/hacktricks-training.md}}

De nombreux challenges avancés de cryptographie en CTF portent sur RSA, la cryptographie à courbes elliptiques (ECC), ECDSA, les réseaux ou les générateurs aléatoires faibles.

## Outils recommandés

- [SageMath](https://www.sagemath.org/) pour l’arithmétique modulaire, les courbes elliptiques et la réduction de réseau<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) pour tester les faiblesses courantes de RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) pour vérifier si un entier possède des facteurs connus<sup>[[3]](#references)</sup>
- La [bibliothèque Python `ecdsa`](https://ecdsa.readthedocs.io/) pour l’analyse de clés, la signature et la vérification<sup>[[7]](#references)</sup>

## RSA

Commencez ici si un challenge fournit `n`, `e` et `c`, ainsi qu’un indice comme un module partagé, un exposant faible, des bits de clé partiels ou des messages liés.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si des signatures sont impliquées, vérifiez la réutilisation, le biais ou la fuite du nonce avant de supposer qu’il faut résoudre le problème du logarithme discret sous-jacent.

### ECDSA nonce reuse / bias

ECDSA exige un nombre secret `k` distinct pour chaque message. Si le même `k` signe deux condensats de message différents, la clé privée peut être retrouvée à partir des valeurs publiques des signatures.<sup>[[4]](#references)</sup>

Même si `k` n’est pas identique, un biais ou une fuite de bits du nonce dans de nombreuses signatures peut permettre une récupération à l’aide de réseaux.<sup>[[5]](#references)</sup>

Récupération technique lorsque `k` est réutilisé :<sup>[[4]](#references)</sup>

Équations de signature ECDSA (ordre du groupe `n`) :

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si le même `k` est réutilisé pour deux messages `m1, m2` produisant les signatures `(r, s1)` et `(r, s2)` :

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocole ne vérifie pas qu’un point fourni appartient à la courbe attendue et au bon sous-groupe, un attaquant peut forcer des opérations dans un groupe plus faible et récupérer des informations sur un scalaire secret. La norme SEC 1 définit des vérifications de validation des clés publiques destinées à empêcher de telles entrées.<sup>[[6]](#references)</sup>

Remarque technique :

- Vérifiez que les points ne sont pas le point à l’infini, que leurs coordonnées sont valides, qu’ils satisfont l’équation de la courbe et qu’ils appartiennent au sous-groupe requis.<sup>[[6]](#references)</sup>
- Dans les challenges CTF, cela se traduit souvent par un serveur qui multiplie un point choisi par l’attaquant par un scalaire secret, puis renvoie une valeur dérivée.

## Clés de signature ML-DSA malformées et fuite par échantillonnage avec rejet

La clé privée étendue de ML-DSA encode les vecteurs polynomiaux `s1` et `s2`, dont les coefficients appartiennent à `[-η, η]`. FIPS 204 indique que le décodage d’octets de clé secrète malformés peut produire des coefficients en dehors de cette plage. L’algorithme de signature n’exige pas à lui seul de vérification supplémentaire de cohérence de la clé privée.<sup>[[8]](#references)</sup>

La condition préalable est de pouvoir contrôler une **clé de signature étendue avant son importation ou son utilisation pour signer**, et non de soumettre une clé publique malformée à un vérificateur. Une procédure d’importation permissive peut accepter des coefficients compactés modifiés et produire malgré tout des signatures valides. Comparez l’acceptation lors de l’importation et de la signature, puis vérifiez les signatures obtenues en suivant le [workflow de fuzzing des encodages de clés cryptographiques](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

La signature calcule `z = y + c·s1` et `r0 = LowBits(w − c·s2)`, puis rejette un candidat lorsque `||z||∞ ≥ γ1 − β` ou `||r0||∞ ≥ γ2 − β`. Ces vérifications rendent les sorties acceptées indépendantes des secrets valides de petite valeur. Des coefficients secrets hors plage peuvent compromettre cet argument d’échantillonnage avec rejet et introduire un biais dépendant du secret. Il s’agit d’un mécanisme de fuite conditionnel, **et non** d’une récupération complète de clé démontrée à partir de l’écart signalé entre les bibliothèques.<sup>[[8]](#references)[[10]](#references)</sup>

La validation de la clé privée est distincte de la vérification de signature. Dans la comparaison signalée, OpenSSL, BoringSSL et SymCrypt appliquaient des vérifications supplémentaires de la clé privée, tandis que liboqs acceptait les clés étendues malformées lors de la signature ; `mldsa-native`, sur lequel il s’appuie, fournit un validateur `pk_from_sk()` que liboqs n’exposait pas. FIPS 204 n’impose pas ces vérifications supplémentaires.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5 : norme relative aux signatures numériques](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner et Heninger : Biased Nonce Sense — attaques par réseau contre les signatures ECDSA faibles](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0 : cryptographie à courbes elliptiques](https://www.secg.org/sec1-v2.pdf)
- [7] [Documentation de la bibliothèque Python `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204 : norme de signature numérique fondée sur les réseaux modulaires](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Vérifications manquantes des clés ML-DSA et ML-KEM - problème liboqs #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [État des implémentations de la cryptographie post-quantique](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
