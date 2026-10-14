# Termes d’investissement

{{#include ../../banners/hacktricks-training.md}}

## Comptant

Le trading au comptant échange un actif contre sa livraison immédiate. Un ordre à cours limité précise la quantité et le prix limite ; il n’est exécuté que lorsque le marché peut respecter ce prix ou proposer un meilleur prix. Un ordre au marché vise plutôt une exécution rapide aux meilleurs prix disponibles et peut subir du slippage.<sup>[[4]](#references)</sup>

Un ordre stop-limit comporte un prix stop qui déclenche un ordre à cours limité. Il peut encadrer le prix d’exécution, mais ne garantit pas l’exécution si le marché dépasse le prix limite.<sup>[[4]](#references)</sup>

## Contrats à terme

Un contrat à terme est un accord standardisé visant à acheter ou vendre une matière première ou un instrument financier déterminé à une date future. Par exemple, deux parties pourraient convenir d’un prix de 70 000 $ pour un bitcoin, avec règlement dans six mois.<sup>[[1]](#references)</sup>

Si le prix de règlement est de 80 000 $, la position longue gagne et la position courte perd par rapport au prix contractuel de 70 000 $. S’il est de 60 000 $, c’est l’inverse. Les contrats à terme négociés en bourse sont réévalués au marché et sont généralement clôturés ou reconduits avant leur échéance ; il s’agit donc d’une illustration simplifiée.<sup>[[2]](#references)</sup>

Les producteurs et les consommateurs utilisent les contrats à terme pour couvrir le risque de prix ; d’autres participants les utilisent pour chercher à réaliser un profit ou fournir de la liquidité.<sup>[[1]](#references)</sup>

- Une **position longue** est généralement profitable lorsque le prix du contrat augmente.
- Une **position courte** est généralement profitable lorsque le prix du contrat baisse.<sup>[[2]](#references)</sup>

### Couverture avec des contrats à terme

Si un gestionnaire de fonds s’attend à une baisse de son portefeuille, il pourrait vendre à découvert un contrat à terme sur indice boursier suffisamment corrélé. Les gains de cette couverture à découvert peuvent compenser une partie des pertes du portefeuille ; le risque de base fait que la compensation est rarement exacte. Un contrat à terme sur bitcoin couvrirait une exposition au bitcoin, et non automatiquement un portefeuille d’actions.

Si le marché couvert baisse, la position courte sur contrats à terme peut gagner de la valeur tandis que les actifs détenus en perdent. S’il monte, les actifs détenus peuvent gagner de la valeur tandis que la couverture en perd. Une couverture réduit certains risques, mais ne garantit pas un profit.<sup>[[1]](#references)</sup>

### Contrats à terme perpétuels

Les contrats perpétuels sont des produits dérivés sans date d’expiration fixe. Les plateformes crypto utilisent couramment des paiements de financement périodiques pour aider à maintenir leur prix près du prix au comptant de l’actif sous-jacent ; les modalités varient selon la plateforme.<sup>[[3]](#references)</sup>

Les profits et les pertes évoluent avec le prix de référence. Une variation de prix de 1 % entraîne une variation d’environ 1 % de la valeur notionnelle de la position, avant frais et paiements de financement, mais l’effet de levier peut représenter un pourcentage beaucoup plus élevé de la garantie déposée.

### Contrats à terme avec effet de levier

L’**effet de levier** permet à un trader de contrôler une position notionnelle plus importante avec un dépôt de marge plus faible. Les pertes ne sont pas toujours limitées à la marge initiale : la liquidation, les écarts de prix, les frais et les règles de la plateforme peuvent entraîner des pertes supplémentaires.<sup>[[3]](#references)</sup>

Par exemple, une marge de 100 $ avec un effet de levier de 50x permet de contrôler une position de 5 000 $. Sans tenir compte des frais, des paiements de financement et des mécanismes de liquidation, une variation favorable de 1 % entraîne un gain de 50 $ (soit 50 % de la marge initiale), tandis qu’une variation défavorable de 1 % entraîne une perte de 50 $. Une variation défavorable de 2 % correspond à 100 $, mais une plateforme liquidera normalement la position avant que toute la marge soit épuisée.

L’effet de levier amplifie les gains comme les pertes et peut entraîner une liquidation après une variation défavorable relativement faible.

## Différences entre les contrats à terme et les options

L’acheteur d’une option reçoit le droit, mais non l’obligation, de l’exercer selon les modalités du contrat. Le vendeur de l’option a l’obligation correspondante si l’acheteur l’exerce. L’acheteur paie au vendeur une prime en échange de ce droit.<sup>[[4]](#references)</sup>

### 1. **Obligation ou droit :**

* **Contrats à terme :** Lorsque vous achetez ou vendez un contrat à terme, vous concluez un **accord contraignant** visant à acheter ou vendre un actif à un prix déterminé à une date future. L’acheteur comme le vendeur sont **tenus** d’exécuter le contrat à l’échéance (sauf si le contrat est clôturé auparavant).
* **Options :** Avec les options, vous avez le **droit, mais non l’obligation**, d’acheter (dans le cas d’une **option d’achat**) ou de vendre (dans le cas d’une **option de vente**) un actif à un prix déterminé, avant ou à une date d’expiration donnée. L’**acheteur** peut choisir d’exercer l’option, tandis que le **vendeur** est tenu d’exécuter la transaction si l’acheteur décide de l’exercer.

### 2. **Risque :**

* **Contrats à terme :** Les deux parties peuvent subir des pertes importantes. Le caractère théoriquement illimité des pertes dépend de la position et de l’actif sous-jacent : une position courte peut entraîner des pertes théoriquement illimitées, tandis qu’une position longue ne peut perdre plus que sa valeur notionnelle si l’actif sous-jacent ne peut pas tomber sous zéro.
* **Options :** L’acheteur qui ne vend pas une autre option ne risque généralement que la prime payée. Le vendeur d’une option d’achat non couverte peut subir des pertes théoriquement illimitées ; les autres stratégies de vente d’options présentent différents profils de risque, limités ou illimités.

### 3. **Coût :**

* **Contrats à terme :** Il n’y a pas de coût initial autre que la marge requise pour maintenir la position, puisque l’acheteur et le vendeur sont tous deux tenus d’effectuer la transaction.
* **Options :** L’acheteur doit payer une **prime d’option** à l’avance pour obtenir le droit d’exercer l’option. Cette prime correspond essentiellement au coût de l’option.

### 4. **Potentiel de profit :**

* **Contrats à terme :** Le profit ou la perte dépend de l’écart entre le prix du marché à l’échéance et le prix convenu dans le contrat.
* **Options :** L’acheteur réalise un profit lorsque le marché évolue favorablement au-delà du prix d’exercice, d’un montant supérieur à la prime payée. Le vendeur réalise un profit en conservant la prime si l’option n’est pas exercée.

## References

- [1] [CFTC - Objectif économique des marchés à terme](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Notions de base sur les marchés à terme](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendre les risques du trading de monnaies virtuelles](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossaire de la CFTC - Option, prime et exercice](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
