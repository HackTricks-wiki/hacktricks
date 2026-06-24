# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Triaging rapide

Collecter :

- `n`, `e`, `c` (et tout ciphertext supplémentaire)
- Toute relation entre les messages (même plaintext ? modulus partagé ? plaintext structuré ?)
- Toute leak (partielle `p/q`, bits de `d`, `dp/dq`, padding connu)

Puis essayer :

- Vérification de factorisation (Factordb / `sage: factor(n)` pour les petits cas)
- Motifs à faible exposant (`e=3`, broadcast)
- Common modulus / repeated primes
- Méthodes de lattice (Coppersmith/LLL) quand quelque chose est presque connu

## Attaques RSA courantes

### Common modulus

Si deux ciphertexts `c1, c2` chiffrent le **même message** sous le **même modulus** `n` mais avec des exposants différents `e1, e2` (et `gcd(e1,e2)=1`), vous pouvez récupérer `m` en utilisant l’algorithme d’Euclide étendu :

`m = c1^a * c2^b mod n` où `a*e1 + b*e2 = 1`.

Exemple de démarche :

1. Calculer `(a, b) = xgcd(e1, e2)` pour obtenir `a*e1 + b*e2 = 1`
2. Si `a < 0`, interpréter `c1^a` comme `inv(c1)^{-a} mod n` (idem pour `b`)
3. Multiplier et réduire modulo `n`

### Shared primes across moduli

Si vous avez plusieurs moduli RSA issus du même challenge, vérifiez s’ils partagent un premier :

- `gcd(n1, n2) != 1` implique une défaillance catastrophique de génération de clé.

Cela apparaît souvent dans les CTF sous la forme de « nous avons généré beaucoup de clés rapidement » ou « mauvaise randomness ».

### Sparse / short-sleeve moduli

Certains générateurs de grands entiers cassés fuient la structure directement dans le modulus public : chaque limb contient seulement un petit sous-espace aléatoire et le reste des bits est `0`. En pratique, cela apparaît comme des **blocs de zéros régulièrement espacés** dans `n`, souvent alignés sur des limbs de 32 bits ou 128 bits.

Vérifications rapides :

- Afficher `n` en hexadécimal et chercher des fenêtres de zéros répétées à un espacement fixe.
- Re-découper `n` en limbs (`2^32`, `2^64`, `2^128`) et inspecter si chaque limb est anormalement petit.
- Auditer les clés SSH/TLS publiques avec un outil comme **badkeys** si vous suspectez une génération faible de host-key.

C’est plus grave qu’un biais statistique : si les deux facteurs privés `p` et `q` sont short-sleeved, le modulus peut devenir **facile à factoriser**.

### Factorisation polynomiale de clés RSA structurées

Pour une largeur de limb suspectée `w`, écrire le modulus en base `B = 2^w` :

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Comme l’évaluation est multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si les facteurs ont aussi des coefficients de limb sparses, alors :

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Démarche d’attaque :

1. Deviner la largeur de limb `w`.
2. Convertir le modulus public `n` en `f_n(x)` en utilisant la base `2^w`.
3. Factoriser `f_n(x)` sur les entiers.
4. Réévaluer les facteurs candidats en `B = 2^w`.
5. Vérifier quels candidats se multiplient pour donner `n`.

Cela **ne casse pas le RSA normal**. Cela ne fonctionne que lorsque les facteurs premiers eux-mêmes ont des coefficients de limb très petits et très structurés.

### Shifted limb leakage

Les bytes sparses ne sont pas toujours alignés au début de chaque limb. Si une conversion directe en base `2^w` produit de gros coefficients, chercher des shifts `i,j` tels que `2^i p` et `2^j q` deviennent sparses dans cette base de limbs. Le polynôme produit peut encore être dérivé du modulus public, factorisé, puis recombiné en facteurs entiers originaux.

### Implementation smell: byte-to-limb RNG bug

Un pattern dangereux consiste à calculer le nombre de **limbs 32-bit**, allouer seulement ce nombre de **bytes**, puis les copier dans le tableau de limbs :
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Cela donne à chaque limb de 32 bits seulement **8 bits d'entropie** plus un bit de tête forcé dans le dernier limb. Les primes RSA résultants peuvent souvent être reconnus et factorisés à partir de la clé publique seule.

### Related DSA failure mode

Si la même routine big-integer défectueuse est réutilisée pour la génération de l'exposant privé DSA, la clé publique `y = g^x` peut exposer un espace de recherche **drastiquement réduit et structuré** pour `x`. Une fois le motif des limbs connu, des attaques de discrete-log comme **baby-step giant-step** peuvent devenir pratiques contre les paramètres publics.

### Håstad broadcast / low exponent

Si le même plaintext est envoyé à plusieurs destinataires avec un petit `e` (souvent `e=3`) et sans padding correct, vous pouvez récupérer `m` via CRT et integer root.

Condition technique :

Si vous avez `e` ciphertexts du même message sous des moduli `n_i` pairwise-coprime :

- Utilisez CRT pour récupérer `M = m^e` sur le produit `N = Π n_i`
- Si `m^e < N`, alors `M` est la vraie puissance entière, et `m = integer_root(M, e)`

### Wiener attack: small private exponent

Si `d` est trop petit, les continued fractions peuvent le récupérer à partir de `e/n`.

### Textbook RSA pitfalls

Si vous voyez :

- Pas de OAEP/PSS, modular exponentiation brute
- Encryption déterministe

alors les algebraic attacks et l'abus d'oracle deviennent beaucoup plus probables.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Si vous voyez deux ciphertexts sous le même modulus avec des messages qui sont algebraically related (par exemple, `m2 = a*m1 + b`), cherchez des attaques de "related-message" comme Franklin–Reiter. Celles-ci nécessitent généralement :

- même modulus `n`
- même exponent `e`
- relation connue entre les plaintexts

En pratique, cela se résout souvent avec Sage en mettant en place des polynomials modulo `n` et en calculant un GCD.

## Lattices / Coppersmith

Utilisez cela lorsque vous avez des bits partiels, un plaintext structuré, ou des relations proches qui rendent l'inconnu petit.

Les méthodes de lattice (LLL/Coppersmith) apparaissent dès que vous avez des informations partielles :

- Plaintext partiellement connu (message structuré avec queue inconnue)
- `p`/`q` partiellement connus (bits de poids fort divulgués)
- Petites différences inconnues entre des valeurs liées

### What to recognize

Indices typiques dans les challenges :

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

En pratique, vous utiliserez Sage pour LLL et un template connu pour l'instance spécifique.

Bon points de départ :

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Une référence de type survey: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
