# Cryptographie à clé publique

{{#include ../../banners/hacktricks-training.md}}

La plupart des hard crypto en CTF se retrouvent ici : RSA, ECC/ECDSA, lattices, et mauvaise randomisation.

## Outils recommandés

- SageMath (LLL/lattices, arithmétique modulaire) : https://www.sagemath.org/
- RsaCtfTool (couteau-suisse) : https://github.com/Ganapati/RsaCtfTool
- factordb (vérifications rapides de facteurs) : http://factordb.com/

## RSA

Commencez ici quand vous avez `n,e,c` et un indice supplémentaire (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Si des signatures sont impliquées, testez d'abord les problèmes de nonce (reuse/bias/leaks) avant de supposer des mathématiques difficiles.

### ECDSA nonce reuse / bias

Si deux signatures réutilisent le même nonce `k`, la clé privée peut être récupérée.

Même si `k` n’est pas identique, **bias/leakage** des bits du nonce entre les signatures peut suffire pour une récupération par lattice (thème courant en CTF).

Récupération technique quand `k` est réutilisé :

Équations de signature ECDSA (ordre du groupe `n`) :

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Si le même `k` est réutilisé pour deux messages `m1, m2` produisant des signatures `(r, s1)` et `(r, s2)` :

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Si un protocole ne valide pas que les points sont sur la courbe attendue (ou dans le sous-groupe), un attaquant peut forcer des opérations dans un groupe faible et récupérer des secrets.

Note technique :

- Vérifier que les points sont sur la courbe et dans le sous-groupe correct.
- Beaucoup de tâches CTF modélisent cela comme "server multiplies attacker-chosen point by secret scalar and returns something."

### Outils

- SageMath pour l'arithmétique des courbes / lattices
- `ecdsa` bibliothèque Python pour le parsing/la vérification

{{#include ../../banners/hacktricks-training.md}}
