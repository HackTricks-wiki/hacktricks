# Termes d’investissement

{{#include ../../banners/hacktricks-training.md}}

## Au comptant

Le trading au comptant échange un actif contre une livraison immédiate. Un ordre à cours limité précise la quantité et le prix limite ; il n’est exécuté que lorsque le marché peut satisfaire ce prix ou en proposer un meilleur. Un ordre au marché vise plutôt une exécution rapide aux meilleurs prix alors disponibles et peut subir du slippage.<sup>[[4]](#references)</sup>

Un ordre stop-limit comporte un prix stop qui déclenche un ordre à cours limité. Il peut encadrer le prix d’exécution, mais ne garantit pas l’exécution si le marché franchit le prix limite.<sup>[[4]](#references)</sup>

## Contrats à terme

Un contrat à terme est un accord normalisé visant à acheter ou vendre une matière première ou un instrument financier donné à une date future. Par exemple, deux parties pourraient convenir d’un prix de 70 000 $ pour un bitcoin, avec un règlement dans six mois.<sup>[[1]](#references)</sup>

Si le prix de règlement est de 80 000 $, la position longue réalise un gain et la position courte une perte par rapport au prix contractuel de 70 000 $. S’il est de 60 000 $, le résultat est inversé. Les contrats à terme négociés en bourse sont réévalués au marché et généralement clôturés ou reconduits avant leur expiration ; il s’agit donc d’un exemple simplifié.<sup>[[2]](#references)</sup>

Les producteurs et les consommateurs utilisent les contrats à terme pour couvrir le risque de prix ; d’autres participants les utilisent pour chercher à réaliser des profits ou à fournir de la liquidité.<sup>[[1]](#references)</sup>

- Une **position longue** est généralement rentable lorsque le prix du contrat augmente.
- Une **position courte** est généralement rentable lorsque le prix du contrat baisse.<sup>[[2]](#references)</sup>

### Couverture avec des contrats à terme

Si un gestionnaire de fonds prévoit une baisse de son portefeuille, il pourrait vendre à découvert un contrat à terme sur indice boursier suffisamment corrélé. Les gains réalisés sur cette couverture courte peuvent compenser une partie des pertes du portefeuille ; le risque de base signifie que la compensation est rarement exacte. Un contrat à terme sur bitcoin couvrirait une exposition au bitcoin, et non automatiquement un portefeuille d’actions.

Si le marché couvert baisse, la position courte sur contrats à terme peut gagner de la valeur tandis que les actifs détenus en perdent. S’il monte, les actifs détenus peuvent gagner de la valeur tandis que la couverture en perd. La couverture réduit certains risques, mais ne garantit pas un profit.<sup>[[1]](#references)</sup>

### Contrats à terme perpétuels

Les contrats perpétuels sont des produits dérivés sans date d’expiration fixe. Les plateformes crypto utilisent couramment des paiements de financement périodiques pour maintenir leur prix près du prix au comptant de l’actif sous-jacent ; les modalités varient selon la plateforme.<sup>[[3]](#references)</sup>

Pour les tests d’abus du taux de financement sur les protocoles de contrats perpétuels on-chain, consultez [Exploitation du taux de financement des contrats perpétuels](perpetual-funding-rate-exploitation.md).

Les profits et les pertes évoluent avec le prix de référence. Une variation de prix de 1 % entraîne une variation d’environ 1 % de la valeur notionnelle de la position, avant frais et paiements de financement, mais l’effet de levier peut représenter un pourcentage bien plus élevé de la garantie déposée.

### Contrats à terme avec effet de levier

L’**effet de levier** permet à un trader de contrôler une position notionnelle plus importante avec un dépôt de marge plus faible. Les pertes ne sont pas toujours limitées à la marge initiale : les liquidations, les écarts de cours, les frais et les règles de la plateforme peuvent entraîner des pertes supplémentaires.<sup>[[3]](#references)</sup>

Par exemple, une marge de 100 $ avec un effet de levier de 50x permet de contrôler une position de 5 000 $. Sans tenir compte des frais, des paiements de financement et des mécanismes de liquidation, une variation favorable de 1 % génère un gain de 50 $ (soit 50 % de la marge initiale), tandis qu’une variation défavorable de 1 % entraîne une perte de 50 $. Une variation défavorable de 2 % correspond à 100 $, mais une plateforme liquidera normalement la position avant l’épuisement de toute la marge.

L’effet de levier amplifie les gains comme les pertes et rend possible une liquidation après une variation défavorable relativement faible.

## Différences entre les contrats à terme et les options

L’acheteur d’une option obtient un droit, et non une obligation, d’exercer l’option selon les conditions du contrat. L’émetteur de l’option a l’obligation correspondante si l’acheteur l’exerce. L’acheteur paie une prime à l’émetteur en échange de ce droit.<sup>[[4]](#references)</sup>

### 1. **Obligation ou droit :**

* **Contrats à terme :** Lorsque vous achetez ou vendez un contrat à terme, vous concluez un **accord contraignant** pour acheter ou vendre un actif à un prix précis à une date future. L’acheteur comme le vendeur sont **tenus** d’exécuter le contrat à son expiration (sauf si le contrat est clôturé avant cette date).
* **Options :** Avec les options, vous avez le **droit, mais pas l’obligation**, d’acheter (dans le cas d’une **option d’achat**) ou de vendre (dans le cas d’une **option de vente**) un actif à un prix précis avant ou à une date d’expiration donnée. L’**acheteur** peut choisir d’exercer l’option, tandis que le **vendeur** est tenu d’exécuter la transaction si l’acheteur décide de l’exercer.

### 2. **Risque :**

* **Contrats à terme :** Les deux parties peuvent subir des pertes importantes. La possibilité que la perte soit mathématiquement illimitée dépend de la position et de l’actif sous-jacent : une position courte peut entraîner une perte théorique illimitée, tandis qu’une position longue ne peut pas perdre plus que sa valeur notionnelle si l’actif sous-jacent ne peut pas tomber sous zéro.
* **Options :** Un acheteur qui n’émet pas d’autre option ne risque généralement que la prime payée. L’émetteur d’une option d’achat non couverte peut subir une perte théoriquement illimitée ; les autres stratégies d’émission d’options présentent différents profils de risque, limités ou illimités.

### 3. **Coût :**

* **Contrats à terme :** Il n’y a pas de coût initial autre que la marge requise pour conserver la position, puisque l’acheteur et le vendeur sont tous deux tenus d’exécuter la transaction.
* **Options :** L’acheteur doit payer une **prime d’option** à l’avance pour obtenir le droit d’exercer l’option. Cette prime correspond essentiellement au coût de l’option.

### 4. **Potentiel de profit :**

* **Contrats à terme :** Le profit ou la perte dépend de la différence entre le prix du marché à l’expiration et le prix convenu dans le contrat.
* **Options :** L’acheteur réalise un profit lorsque le marché évolue en sa faveur au-delà du prix d’exercice, et ce, d’un montant supérieur à la prime payée. Le vendeur réalise un profit en conservant la prime si l’option n’est pas exercée.

## References

- [1] [CFTC - L’objectif économique des marchés à terme](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Principes de base des marchés à terme](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendre les risques du trading de monnaies virtuelles](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossaire de la CFTC - Option, prime et exercice](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
