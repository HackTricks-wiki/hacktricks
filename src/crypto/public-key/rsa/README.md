# Attaques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapide

Collectez :

- `n`, `e`, `c` (ainsi que tous les ciphertexts supplémentaires)
- Toutes les relations entre les messages (même plaintext ? modulus partagé ? plaintext structuré ?)
- Tous les leaks (partiel `p/q`, bits de `d`, `dp/dq`, padding connu)

Essayez ensuite :

- Vérification de la factorisation (Factordb / `sage: factor(n)` pour les valeurs relativement petites)
- Motifs liés aux petits exposants (`e=3`, broadcast)
- Modulus commun / primes répétées
- Méthodes par lattice (Coppersmith/LLL) lorsqu'une partie est presque connue

## Attaques RSA courantes

### Modulus commun

Si deux ciphertexts `c1, c2` chiffrent le **même message** avec le **même modulus** `n`, mais avec des exposants différents `e1, e2` (et `gcd(e1,e2)=1`), vous pouvez récupérer `m` à l'aide de l'algorithme d'Euclide étendu :

`m = c1^a * c2^b mod n` où `a*e1 + b*e2 = 1`.

Exemple :

1. Calculez `(a, b) = xgcd(e1, e2)` afin que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interprétez `c1^a` comme `inv(c1)^{-a} mod n` (même chose pour `b`)
3. Multipliez et réduisez modulo `n`

### Primes partagées entre les moduli

Si vous avez plusieurs moduli RSA provenant du même challenge, vérifiez s'ils partagent un prime :

- `gcd(n1, n2) != 1` implique une défaillance catastrophique de la génération de clés.

Cela apparaît fréquemment dans les CTFs sous la forme « nous avons généré beaucoup de clés rapidement » ou « mauvaise randomness ».

### Moduli sparse / short-sleeve

Certains générateurs d'entiers de grande taille défectueux leakent directement une structure dans le modulus public : chaque limb ne contient qu'un petit sous-champ aléatoire, le reste des bits étant à `0`. En pratique, cela se manifeste par des blocs de zéros **régulièrement espacés** dans `n`, souvent alignés sur des limbs de 32 ou 128 bits.<sup>[[1]](#references)</sup>

Vérifications rapides :

- Affichez `n` en hexadécimal et recherchez des fenêtres de zéros répétées avec un stride fixe.
- Re-découpez `n` en limbs (`2^32`, `2^64`, `2^128`) et vérifiez si chaque limb est inhabituellement petit.
- Auditez les clés SSH/TLS publiques avec des outils tels que **badkeys** lorsque vous suspectez une génération faible de clés d'hôte.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

C'est plus grave qu'un biais statistique : si les deux facteurs privés `p` et `q` sont short-sleeve, le modulus peut devenir **facile à factoriser**.<sup>[[1]](#references)</sup>

### Factorisation polynomiale de clés RSA structurées

Pour une largeur de limb suspectée `w`, écrivez le modulus en base `B = 2^w` :

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Comme l'évaluation est multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si les facteurs possèdent également des coefficients de limbs sparse, alors :

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Déroulement de l'attaque :

1. Devinez la largeur de limb `w`.
2. Convertissez le modulus public `n` en `f_n(x)` en utilisant la base `2^w`.
3. Factorisez `f_n(x)` sur les entiers.
4. Réévaluez les facteurs candidats en `B = 2^w`.
5. Vérifiez quels candidats se multiplient pour donner `n`.

Cela **ne casse pas RSA normal**. Cela fonctionne uniquement lorsque les facteurs premiers eux-mêmes possèdent des coefficients de limbs très petits et fortement structurés.<sup>[[1]](#references)</sup>

### Leak de limbs décalés

Les octets sparse ne sont pas toujours alignés sur l'extrémité basse de chaque limb. Si la conversion directe en base `2^w` produit de grands coefficients, recherchez des décalages `i,j` tels que `2^i p` et `2^j q` deviennent sparse dans cette base de limbs. Le polynôme produit peut toujours être dérivé du modulus public, factorisé, puis recombiné pour retrouver les facteurs entiers d'origine.<sup>[[1]](#references)</sup>

### Indice d'implémentation : bug du RNG lors de la conversion octet-vers-limb

Un schéma dangereux consiste à calculer le nombre de **limbs de 32 bits**, à n'allouer que ce nombre d'**octets**, puis à les copier dans le tableau de limbs :
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Cela ne donne à chaque limb de 32 bits que **8 bits d'entropie**, plus un bit de tête forcé dans le dernier limb. Les nombres premiers RSA obtenus peuvent souvent être reconnus et factorisés à partir de la clé publique seule.<sup>[[1]](#references)</sup>

### Mode d'échec DSA associé

Si la même routine big-integer défectueuse est réutilisée pour générer l'exposant privé DSA, la clé publique `y = g^x` peut révéler un espace de recherche pour `x` **considérablement réduit et structuré**. Une fois le motif des limbs connu, les attaques de logarithme discret telles que **baby-step giant-step** peuvent devenir pratiques contre les paramètres publics.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Si le même plaintext est envoyé à plusieurs destinataires avec un petit `e` (souvent `e=3`) et sans padding correct, vous pouvez récupérer `m` via CRT et une racine entière.

Condition technique :

Si vous avez `e` ciphertexts du même message sous des moduli `n_i` premiers entre eux deux à deux :

- Utilisez CRT pour récupérer `M = m^e` sur le produit `N = Π n_i`
- Si `m^e < N`, alors `M` est la véritable puissance entière, et `m = integer_root(M, e)`

### Wiener attack: small private exponent

Si `d` est trop petit, les fractions continues peuvent permettre de le récupérer à partir de `e/n`.

### Pièges du textbook RSA

Si vous voyez :

- Pas d'OAEP/PSS, modular exponentiation brute
- Chiffrement déterministe

alors les attaques algébriques et l'abus d'oracles deviennent beaucoup plus probables.

### Outils

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Motifs de messages associés

Si vous voyez deux ciphertexts sous le même modulus avec des messages liés algébriquement (par exemple, `m2 = a*m1 + b`), recherchez des attaques de type "related-message", telles que Franklin–Reiter. Elles nécessitent généralement :

- le même modulus `n`
- le même exponent `e`
- une relation connue entre les plaintexts

En pratique, cela se résout souvent avec Sage en configurant des polynômes modulo `n` et en calculant un GCD.

## Réseaux / Coppersmith

Utilisez cette approche lorsque vous disposez de bits partiels, d'un plaintext structuré ou de relations proches qui rendent l'inconnue petite.

Les méthodes de lattice (LLL/Coppersmith) apparaissent dès que vous disposez d'informations partielles :

- Plaintext partiellement connu (message structuré avec une fin inconnue)
- `p`/`q` partiellement connus (bits de poids fort leakés)
- Petites différences inconnues entre des valeurs liées

### Ce qu'il faut reconnaître

Indices typiques dans les challenges :

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Outils

En pratique, vous utiliserez Sage pour LLL ainsi qu'un template connu pour l'instance spécifique.

Bons points de départ :

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factorisation des clés RSA "short-sleeve" avec des polynômes](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [outil autonome badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
