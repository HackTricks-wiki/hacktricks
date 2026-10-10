# Attaques RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage rapide

Collectez :

- `n`, `e`, `c` (et tout ciphertext supplémentaire)
- Toute relation entre les messages (même plaintext ? modulus partagé ? plaintext structuré ?)
- Toute fuite (partielle de `p/q`, bits de `d`, `dp/dq`, padding connu)

Essayez ensuite :

- Vérifier la factorisation (Factordb / `sage: factor(n)` pour les nombres relativement petits)
- Repérer les motifs liés à un faible exposant (`e=3`, broadcast)
- Rechercher un modulus commun / des nombres premiers répétés
- Utiliser des méthodes de réseau (Coppersmith/LLL) lorsqu’une partie est presque connue

## Attaques RSA courantes

### Common modulus

Si deux ciphertexts `c1, c2` chiffrent le **même message** avec le **même modulus** `n`, mais avec des exposants différents `e1, e2` (et `gcd(e1,e2)=1`), vous pouvez retrouver `m` à l’aide de l’algorithme d’Euclide étendu :

`m = c1^a * c2^b mod n` où `a*e1 + b*e2 = 1`.

Exemple de procédure :

1. Calculez `(a, b) = xgcd(e1, e2)` de sorte que `a*e1 + b*e2 = 1`
2. Si `a < 0`, interprétez `c1^a` comme `inv(c1)^{-a} mod n` (même chose pour `b`)
3. Multipliez et réduisez modulo `n`

### Nombres premiers partagés entre plusieurs moduli

Si vous avez plusieurs moduli RSA issus du même challenge, vérifiez s’ils partagent un nombre premier :

- `gcd(n1, n2) != 1` implique une défaillance catastrophique de la génération de clés.

Cela se produit souvent dans les CTF avec des explications comme « nous avons généré rapidement de nombreuses clés » ou « mauvais aléatoire ».

### Moduli clairsemés / short-sleeve

Certains générateurs défectueux de grands entiers divulguent directement une structure dans le modulus public : chaque limb contient uniquement un petit sous-champ aléatoire, le reste des bits étant à `0`. En pratique, cela se manifeste par des **blocs de zéros régulièrement espacés** dans `n`, souvent alignés sur des limbs de 32 ou 128 bits.<sup>[[1]](#references)</sup>

Vérifications rapides :

- Affichez `n` en hexadécimal et recherchez des fenêtres de zéros répétées à intervalles fixes.
- Redécoupez `n` en limbs (`2^32`, `2^64`, `2^128`) et vérifiez si chaque limb est anormalement petit.
- Auditez les clés SSH/TLS publiques avec des outils comme **badkeys** si vous soupçonnez une génération de clés d’hôte faible.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

C’est plus grave qu’un biais statistique : si les deux facteurs privés `p` et `q` sont short-sleeve, le modulus peut devenir **facile à factoriser**.<sup>[[1]](#references)</sup>

### Factorisation polynomiale de clés RSA structurées

Pour une largeur de limb supposée `w`, écrivez le modulus en base `B = 2^w` :

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Comme l’évaluation est multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Si les facteurs ont également des coefficients de limb clairsemés, alors :

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Procédure d’attaque :

1. Devinez la largeur de limb `w`.
2. Convertissez le modulus public `n` en `f_n(x)` en utilisant la base `2^w`.
3. Factorisez `f_n(x)` sur les entiers.
4. Évaluez les facteurs candidats en `B = 2^w`.
5. Vérifiez quels candidats, multipliés entre eux, donnent `n`.

Cela **ne casse pas le RSA normal**. Cette méthode ne fonctionne que lorsque les facteurs premiers eux-mêmes ont des coefficients de limb très petits et fortement structurés.<sup>[[1]](#references)</sup>

### Fuite de limbs décalés

Les octets clairsemés ne sont pas toujours alignés sur le début de chaque limb. Si la conversion directe en base `2^w` produit de grands coefficients, recherchez des décalages `i,j` tels que `2^i p` et `2^j q` deviennent clairsemés dans cette base de limbs. Le polynôme produit peut toujours être dérivé du modulus public, factorisé, puis recombiné pour retrouver les facteurs entiers d’origine.<sup>[[1]](#references)</sup>

### Indice d’implémentation : bug du RNG dans la conversion octets-vers-limbs

Un schéma dangereux consiste à calculer le nombre de **limbs de 32 bits**, à n’allouer que ce nombre d’**octets**, puis à les copier dans le tableau de limbs :

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Cela donne à chaque limb de 32 bits seulement **8 bits d’entropie**, plus un bit de poids fort forcé dans le dernier limb. Les nombres premiers RSA obtenus peuvent souvent être reconnus et factorisés à partir de la seule clé publique.<sup>[[1]](#references)</sup>

### Mode de défaillance DSA associé

Si la même routine défectueuse pour les grands entiers est réutilisée pour générer l’exposant privé DSA, la clé publique `y = g^x` peut leak un espace de recherche pour `x` **considérablement réduit et structuré**. Une fois le motif des limbs connu, les attaques par logarithme discret telles que **baby-step giant-step** peuvent devenir pratiques contre les paramètres publics.<sup>[[1]](#references)</sup>

### Attaque broadcast de Håstad / exposant faible

Si le même texte clair est envoyé à plusieurs destinataires avec un petit `e` (souvent `e=3`) et sans padding adapté, vous pouvez récupérer `m` via CRT et une racine entière.

Condition technique :

Si vous avez `e` textes chiffrés du même message avec des modules `n_i` premiers entre eux deux à deux :

- Utilisez CRT pour récupérer `M = m^e` modulo le produit `N = Π n_i`
- Si `m^e < N`, alors `M` est la véritable puissance entière, et `m = integer_root(M, e)`

### Attaque de Wiener : exposant privé faible

Si `d` est trop petit, les fractions continues peuvent le retrouver à partir de `e/n`.

### Pièges du RSA textbook

Si vous voyez :

- Pas d’OAEP/PSS, exponentiation modulaire brute
- Chiffrement déterministe

les attaques algébriques et l’exploitation d’oracles deviennent alors beaucoup plus probables.

### Outils

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, racines, fractions continues) : https://www.sagemath.org/

## Motifs à messages associés

Si vous voyez deux textes chiffrés avec le même module et des messages liés algébriquement (par exemple, `m2 = a*m1 + b`), cherchez des attaques à « messages associés », comme Franklin–Reiter. Elles nécessitent généralement :

- le même module `n`
- le même exposant `e`
- une relation connue entre les textes clairs

En pratique, cela se résout souvent avec Sage en définissant des polynômes modulo `n` et en calculant un PGCD.

## Réseaux / Coppersmith

Utilisez cette approche lorsque vous disposez de bits partiels, d’un texte clair structuré ou de relations proches qui rendent l’inconnue petite.

Les méthodes par réseaux (LLL/Coppersmith) interviennent dès que vous disposez d’informations partielles :

- Texte clair partiellement connu (message structuré avec une fin inconnue)
- `p`/`q` partiellement connu (bits de poids fort leakés)
- Petites différences inconnues entre des valeurs associées

### Éléments à reconnaître

Indices typiques dans les challenges :

- « Nous avons leaké les bits de poids fort/faible de p »
- « Le flag est intégré ainsi : `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")` »
- « Nous avons utilisé RSA avec un petit padding aléatoire »

### Outils

En pratique, vous utiliserez Sage pour LLL et un modèle connu adapté au cas particulier.

Pour commencer :

- Modèles cryptographiques CTF pour Sage : https://github.com/defund/coppersmith
- Référence de type survey : https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factorisation des clés RSA « short-sleeve » avec des polynômes](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Outil autonome badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

