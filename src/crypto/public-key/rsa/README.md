# RSA Attaques

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapide

Collecter :

- `n`, `e`, `c` (et tout ciphertext supplémentaire)
- Toute relation entre messages (same plaintext ? shared modulus ? structured plaintext ?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Puis essayer :

- Vérifier la factorisation (Factordb / `sage: factor(n)` pour des n relativement petits)
- Motifs d'exposant faible (`e=3`, broadcast)
- Modulus commun / primes répétées
- Méthodes par réseaux (Coppersmith/LLL) quand une partie est presque connue

## Attaques RSA courantes

### Common modulus

Si deux ciphertexts `c1, c2` chiffrent le même message sous le même modulus `n` mais avec des exposants différents `e1, e2` (et `gcd(e1,e2)=1`), vous pouvez récupérer `m` en utilisant l'algorithme d'Euclide étendu :

`m = c1^a * c2^b mod n` où `a*e1 + b*e2 = 1`.

Exemple, en bref :

1. Calculer `(a, b) = xgcd(e1, e2)` de sorte que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpréter `c1^a` comme `inv(c1)^{-a} mod n` (de même pour `b`)
3. Multiplier et réduire modulo `n`

### Shared primes across moduli

Si vous avez plusieurs moduli RSA provenant du même challenge, vérifiez s'ils partagent un premier :

- `gcd(n1, n2) != 1` implique une défaillance catastrophique de génération de clés.

On le voit souvent dans les CTFs quand "nous avons généré beaucoup de clés rapidement" ou "mauvaise randomness".

### Håstad broadcast / low exponent

Si le même plaintext est envoyé à plusieurs destinataires avec un petit `e` (souvent `e=3`) et sans padding correct, vous pouvez récupérer `m` via CRT et racine entière.

Condition technique :

Si vous avez `e` ciphertexts du même message sous des moduli deux à deux coprimes `n_i` :

- Utiliser CRT pour reconstruire `M = m^e` sur le produit `N = Π n_i`
- Si `m^e < N`, alors `M` est la véritable puissance entière, et `m = integer_root(M, e)`

### Wiener attack: small private exponent

Si `d` est trop petit, les fractions continues peuvent le récupérer à partir de `e/n`.

### Textbook RSA pitfalls

Si vous voyez :

- Pas d'OAEP/PSS, exponentiation modulaire brute
- Chiffrement déterministe

alors les attaques algébriques et l'abus d'oracles deviennent beaucoup plus probables.

### Outils

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Patterns de messages liés

Si vous observez deux ciphertexts sous le même modulus avec des messages algébriquement liés (par ex., `m2 = a*m1 + b`), cherchez des attaques "related-message" comme Franklin–Reiter. Celles-ci nécessitent typiquement :

- même modulus `n`
- même exposant `e`
- relation connue entre les plaintexts

En pratique, on résout souvent ça avec Sage en posant des polynômes modulo `n` et en calculant un GCD.

## Lattices / Coppersmith

Recourez à cela quand vous avez des bits partiels, un plaintext structuré, ou des relations proches qui rendent l'inconnu petit.

Les méthodes par réseaux (LLL/Coppersmith) apparaissent chaque fois que vous avez une information partielle :

- Plaintext partiellement connu (message structuré avec une queue inconnue)
- `p`/`q` partiellement connus (bits hauts divulgués)
- Petites différences inconnues entre valeurs liées

### Ce qu'il faut reconnaître

Indices typiques dans les challenges :

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Outils

En pratique vous utiliserez Sage pour LLL et un template connu pour l'instance spécifique.

Bonnes bases :

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Une référence de type survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
