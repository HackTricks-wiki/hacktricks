# Termes d’investissement

{{#include ../banners/hacktricks-training.md}}

## Spot

C’est la manière la plus basique de faire du trading. Vous pouvez **indiquer le montant de l’actif et le prix** auxquels vous souhaitez acheter ou vendre, et dès que ce prix est atteint, l’opération est effectuée.

Vous pouvez généralement aussi utiliser le **prix actuel du marché** afin d’effectuer la transaction aussi rapidement que possible au prix actuel.

**Stop Loss - Limit** : Vous pouvez également indiquer le montant et le prix des actifs à acheter ou à vendre, tout en indiquant un prix inférieur auquel acheter ou vendre s’il est atteint (pour limiter les pertes).

## Contrats à terme

Un contrat à terme est un contrat dans lequel 2 parties se mettent d’accord pour **acquérir quelque chose dans le futur à un prix fixe**. Par exemple, vendre 1 bitcoin dans 6 mois pour 70 000 $.

Évidemment, si dans 6 mois la valeur du bitcoin est de 80 000 $, le vendeur perd de l’argent et l’acheteur en gagne. Si dans 6 mois la valeur du bitcoin est de 60 000 $, c’est l’inverse qui se produit.

Cependant, cela peut être intéressant, par exemple, pour les entreprises qui fabriquent un produit et doivent avoir la garantie de pouvoir le vendre à un prix leur permettant de couvrir leurs coûts. Cela peut également intéresser les entreprises qui souhaitent garantir des prix fixes à l’avenir pour un produit, même si ces prix sont plus élevés.

Bien que, sur les exchanges, cette méthode soit généralement utilisée pour essayer de réaliser un bénéfice.

* Notez qu’une « position longue » signifie que quelqu’un parie sur une hausse du prix
* Tandis qu’une « position short » signifie que quelqu’un parie sur une baisse du prix

### Couverture avec des contrats à terme <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Si un gestionnaire de fonds craint que certaines actions baissent, il peut prendre une position short sur certains actifs, comme des bitcoins ou des contrats à terme sur le S\&P 500. Cela revient à acheter ou à détenir certains actifs et à créer un contrat prévoyant de les vendre à une date ultérieure à un prix plus élevé.

Si le prix baisse, le gestionnaire de fonds réalisera un bénéfice, car il vendra les actifs à un prix plus élevé. Si le prix des actifs augmente, le gestionnaire ne réalisera pas ce bénéfice, mais conservera ses actifs.

### Contrats à terme perpétuels

**Ce sont des « contrats à terme » qui durent indéfiniment** (sans date de fin de contrat). Il est très courant d’en trouver, par exemple, sur les exchanges crypto, où vous pouvez entrer et sortir de contrats à terme en fonction du prix des cryptomonnaies.

Notez que, dans ces cas, les bénéfices et les pertes peuvent être réalisés en temps réel : si le prix augmente de 1 %, vous gagnez 1 % ; si le prix baisse de 1 %, vous le perdez.

### Contrats à terme avec effet de levier

**L’effet de levier** vous permet de contrôler une position plus importante sur le marché avec une somme d’argent plus faible. Il vous permet essentiellement de « parier » beaucoup plus d’argent que vous n’en possédez, en ne risquant que l’argent dont vous disposez réellement.

Par exemple, si vous ouvrez une position future sur la paire BTC/USDT avec 100 $ et un effet de levier de 50x, cela signifie que si le prix augmente de 1 %, vous gagnerez 1x50 = 50 % de votre investissement initial (50 $). Vous disposerez donc de 150 $.\
Cependant, si le prix baisse de 1 %, vous perdrez 50 % de vos fonds (59 $ dans ce cas). Et si le prix baisse de 2 %, vous perdrez la totalité de votre mise (2x50 = 100 %).

Ainsi, l’effet de levier permet de contrôler le montant d’argent misé tout en augmentant les gains et les pertes.

## Différences entre les contrats à terme et les options

La principale différence entre les contrats à terme et les options est que le contrat est facultatif pour l’acheteur : il peut décider de l’exécuter ou non (généralement, il ne l’exécutera que si cela lui est favorable). Le vendeur doit vendre si l’acheteur souhaite utiliser l’option.\
Cependant, l’acheteur paiera des frais au vendeur pour ouvrir l’option (le vendeur, qui prend apparemment davantage de risques, commence donc à gagner de l’argent).

### 1. **Obligation contre droit :**

* **Contrats à terme :** Lorsque vous achetez ou vendez un contrat à terme, vous concluez un **accord contraignant** pour acheter ou vendre un actif à un prix donné à une date future. L’acheteur et le vendeur sont tous deux **obligés** d’exécuter le contrat à son expiration (sauf si le contrat est clôturé avant cette date).
* **Options :** Avec les options, vous avez le **droit, mais pas l’obligation**, d’acheter (dans le cas d’une **option call**) ou de vendre (dans le cas d’une **option put**) un actif à un prix donné avant ou à une certaine date d’expiration. L’**acheteur** a la possibilité d’exécuter l’option, tandis que le **vendeur** est obligé d’effectuer la transaction si l’acheteur décide d’exercer l’option.

### 2. **Risque :**

* **Contrats à terme :** L’acheteur et le vendeur prennent tous deux un **risque illimité**, car ils sont obligés d’exécuter le contrat. Le risque correspond à la différence entre le prix convenu et le prix du marché à la date d’expiration.
* **Options :** Le risque de l’acheteur est limité à la **prime** payée pour acheter l’option. Si le marché n’évolue pas en faveur du détenteur de l’option, celui-ci peut simplement laisser l’option expirer. Cependant, le **vendeur** (émetteur) de l’option prend un risque illimité si le marché évolue fortement contre lui.

### 3. **Coût :**

* **Contrats à terme :** Il n’y a pas de coût initial au-delà de la marge requise pour conserver la position, puisque l’acheteur et le vendeur sont tous deux obligés d’effectuer la transaction.
* **Options :** L’acheteur doit payer d’avance une **prime d’option** pour obtenir le droit d’exercer l’option. Cette prime constitue essentiellement le coût de l’option.

### 4. **Potentiel de profit :**

* **Contrats à terme :** Le bénéfice ou la perte dépend de la différence entre le prix du marché à l’expiration et le prix convenu dans le contrat.
* **Options :** L’acheteur réalise un bénéfice lorsque le marché évolue favorablement au-delà du prix d’exercice, et ce mouvement dépasse le montant de la prime payée. Le vendeur réalise un bénéfice en conservant la prime si l’option n’est pas exercée.

{{#include ../banners/hacktricks-training.md}}
