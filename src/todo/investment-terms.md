# Termes d'investissement

{{#include ../banners/hacktricks-training.md}}

## Spot

Le trading Spot échange un actif contre une livraison immédiate. Un ordre à cours limité spécifie la quantité et le prix limite ; il ne s'exécute que lorsque le marché peut satisfaire ce prix ou proposer un meilleur prix. Un ordre au marché cherche au contraire une exécution rapide aux meilleurs prix alors disponibles et peut subir du slippage.<sup>[[4]](#references)</sup>

Un ordre stop-limit possède un prix stop qui active un ordre à cours limité. Il peut contraindre le prix d'exécution, mais ne garantit pas l'exécution si le marché traverse la limite.<sup>[[4]](#references)</sup>

## Futures

Un contrat futures est un accord standardisé visant à acheter ou vendre une matière première ou un instrument financier spécifié à une date ultérieure. Par exemple, deux parties pourraient convenir d'un prix de 70 000 $ pour un bitcoin, avec un règlement dans six mois.<sup>[[1]](#references)</sup>

Si le prix de règlement est de 80 000 $, la position longue gagne et la position courte perd par rapport au prix contractuel de 70 000 $. S'il est de 60 000 $, le sens est inversé. Les futures réellement négociés en bourse sont évalués au prix du marché et généralement clôturés ou reconduits avant leur expiration ; il s'agit donc d'une illustration simplifiée.<sup>[[2]](#references)</sup>

Les producteurs et les consommateurs utilisent les futures pour couvrir le risque de prix ; d'autres participants les utilisent pour chercher à réaliser un profit ou fournir de la liquidité.<sup>[[1]](#references)</sup>

- Une **position longue** est généralement bénéficiaire lorsque le prix du contrat augmente.
- Une **position courte** est généralement bénéficiaire lorsque le prix du contrat baisse.<sup>[[2]](#references)</sup>

### Couverture avec des futures

Si un gestionnaire de fonds s'attend à une baisse d'un portefeuille, il peut vendre à découvert un contrat futures sur indice boursier suffisamment corrélé. Les gains de la couverture courte peuvent compenser une partie des pertes du portefeuille ; le risque de base signifie que la compensation est rarement exacte. Un future sur bitcoin couvrirait une exposition au bitcoin, mais pas automatiquement un portefeuille d'actions.

Si le marché couvert baisse, la position courte sur futures peut gagner de la valeur tandis que les actifs détenus en perdent. S'il augmente, les actifs détenus peuvent prendre de la valeur tandis que la couverture en perd. La couverture réduit un risque donné plutôt qu'elle ne crée un profit garanti.<sup>[[1]](#references)</sup>

### Futures perpétuels

Les contrats perpétuels sont des dérivés sans date d'expiration fixe. Les plateformes crypto utilisent couramment des paiements périodiques de funding pour maintenir leur prix proche du prix Spot sous-jacent ; les conditions varient selon la plateforme.<sup>[[3]](#references)</sup>

Les profits et pertes évoluent avec le prix de référence. Un mouvement de prix de 1 % produit approximativement un mouvement de 1 % de la valeur notionnelle de la position avant les frais et le funding, mais l'effet de levier peut en faire un pourcentage beaucoup plus important de la garantie déposée.

### Futures avec effet de levier

L'**effet de levier** permet à un trader de contrôler une position notionnelle plus importante avec un dépôt de marge inférieur. Les pertes ne sont pas toujours limitées à la marge initiale : la liquidation, les gaps, les frais et les règles de la plateforme peuvent entraîner des pertes supplémentaires.<sup>[[3]](#references)</sup>

Par exemple, une marge de 100 $ avec un effet de levier de 50x contrôle une position de 5 000 $. En ignorant les frais, le funding et les mécanismes de liquidation, un mouvement favorable de 1 % produit un gain de 50 $ (50 % de la marge initiale), tandis qu'un mouvement défavorable de 1 % produit une perte de 50 $. Un mouvement défavorable de 2 % correspond à 100 $, bien qu'une plateforme liquide normalement la position avant que toute la marge soit épuisée.

L'effet de levier amplifie à la fois les gains et les pertes et rend la liquidation possible après un mouvement défavorable relativement faible.

## Différences entre les futures et les options

L'acheteur d'une option reçoit un droit, et non une obligation, d'exercer selon les conditions du contrat. Le vendeur de l'option a l'obligation correspondante si l'acheteur exerce son droit. L'acheteur paie au vendeur une prime pour ce droit.<sup>[[4]](#references)</sup>

### 1. **Obligation contre droit :**

* **Futures :** Lorsque vous achetez ou vendez un contrat futures, vous concluez un **accord contraignant** pour acheter ou vendre un actif à un prix spécifique à une date ultérieure. L'acheteur et le vendeur sont tous deux **obligés** d'exécuter le contrat à son expiration (sauf si le contrat est clôturé auparavant).
* **Options :** Avec les options, vous avez le **droit, mais pas l'obligation**, d'acheter (dans le cas d'une **option call**) ou de vendre (dans le cas d'une **option put**) un actif à un prix spécifique avant ou à une certaine date d'expiration. L'**acheteur** peut choisir d'exécuter l'option, tandis que le **vendeur** est obligé d'exécuter la transaction si l'acheteur décide d'exercer l'option.

### 2. **Risque :**

* **Futures :** Les deux parties peuvent subir des pertes importantes. Le fait que la perte soit mathématiquement illimitée dépend de la position et de l'actif sous-jacent : une position courte peut avoir une perte théorique non bornée, tandis qu'une position longue ne peut pas perdre plus que la valeur notionnelle si le sous-jacent ne peut pas descendre en dessous de zéro.
* **Options :** Un acheteur qui ne vend pas lui-même une autre option risque généralement la prime payée. Le vendeur d'une option call non couverte peut subir une perte théoriquement illimitée ; les autres stratégies de vente d'options présentent des profils de risque bornés ou non bornés différents.

### 3. **Coût :**

* **Futures :** Il n'y a pas de coût initial au-delà de la marge requise pour conserver la position, puisque l'acheteur et le vendeur sont tous deux obligés de finaliser la transaction.
* **Options :** L'acheteur doit payer d'avance une **prime d'option** pour obtenir le droit d'exercer l'option. Cette prime constitue essentiellement le coût de l'option.

### 4. **Potentiel de profit :**

* **Futures :** Le profit ou la perte dépend de la différence entre le prix du marché à l'expiration et le prix convenu dans le contrat.
* **Options :** L'acheteur réalise un profit lorsque le marché évolue favorablement au-delà du prix d'exercice d'un montant supérieur à la prime payée. Le vendeur réalise un profit en conservant la prime si l'option n'est pas exercée.

## References

- [1] [CFTC - L'objectif économique des marchés futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Principes fondamentaux des marchés futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprendre les risques du trading de devises virtuelles](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossaire de la CFTC - Option, prime et exercice](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
