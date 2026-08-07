# Cryptographie à clé publique

{{#include ../../banners/hacktricks-training.md}}


La plupart des challenges de cryptographie complexes des CTF aboutissent ici : RSA, ECC/ECDSA, lattices et mauvaise randomisation.

## Outils recommandés

- SageMath (LLL/lattices, arithmétique modulaire) : https://www.sagemath.org/
- RsaCtfTool (couteau suisse) : https://github.com/Ganapati/RsaCtfTool
- factordb (vérifications rapides de facteurs) : http://factordb.com/

## RSA

Commencez ici lorsque vous disposez de `n,e,c` et d'un indice supplémentaire (modulus partagé, exposant faible, bits partiels, messages liés).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si des signatures sont impliquées, testez d'abord les problèmes de nonce (réutilisation/biais/leaks) avant de supposer qu'il s'agit de mathématiques difficiles.

### Réutilisation / biais du nonce ECDSA

Si deux signatures réutilisent le même nonce `k`, la clé privée peut être récupérée.

Même si `k` n'est pas identique, le **biais/leakage** de bits du nonce entre les signatures peut suffire pour une récupération par lattice (thème courant des CTF).

Récupération technique lorsque `k` est réutilisé :

Équations de signature ECDSA (ordre du groupe `n`) :

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si le même `k` est réutilisé pour deux messages `m1, m2` produisant les signatures `(r, s1)` et `(r, s2)` :

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Attaques invalid-curve

Si un protocole ne vérifie pas que les points sont sur la courbe attendue (ou dans le sous-groupe), un attaquant peut forcer les opérations dans un groupe faible et récupérer des secrets.

Note technique :

- Vérifiez que les points sont sur la courbe et dans le sous-groupe correct.
- De nombreuses tâches de CTF modélisent cela comme suit : « le serveur multiplie un point choisi par l'attaquant par un scalaire secret et renvoie quelque chose ».

### Outils

- SageMath pour l'arithmétique des courbes / lattices
- Bibliothèque Python `ecdsa` pour l'analyse et la vérification

{{#include ../../banners/hacktricks-training.md}}
