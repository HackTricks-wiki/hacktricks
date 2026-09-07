# Divergence d'état et contournements d'autorisation par valeur par défaut

{{#include ../../banners/hacktricks-training.md}}

L'autorisation dépend parfois d'un état économique dérivé plutôt que d'un rôle explicite — par exemple, « l'appelant possède la totalité de l'offre ». Si les valeurs de ce prédicat proviennent de différents stockages, un doublon obsolète peut transformer un raccourci de propriété légitime en contournement d'autorisation. Le module de marqueur Provenance a démontré cette combinaison dangereuse : le solde actuel de l'appelant était comparé aux métadonnées d'offre locales au marqueur, qui n'étaient pas mises à jour pour les assets dont l'offre n'était pas fixe.<sup>[[1]](#references)</sup>

## Auditer les états dupliqués comme frontière d'autorisation

Pour chaque valeur utilisée par un contrôle de permission, énumérez **toutes les représentations** : état canonique du module, champs des objets, agrégats mis en cache, index, snapshots, enregistrements de bridge et miroirs off-chain. Suivez ensuite chaque chemin de création, mint, burn, transfert, réinitialisation, migration et synchronisation afin de déterminer quelle copie est mise à jour dans chaque mode d'objet. Un champ peut faire autorité dans un mode et être informatif dans un autre.<sup>[[1]](#references)</sup>

Une procédure pratique d'audit est la suivante :<sup>[[1]](#references)</sup>

1. Localisez les actions protégées et réduisez chaque branche d'autorisation à un prédicat booléen.
2. Pour chaque opérande, consignez son stockage, ses chemins de mise à jour, ses états du cycle de vie et sa source de vérité.
3. Générez des transitions qui ne mettent à jour qu'une seule représentation, puis comparez toutes les copies.
4. Tentez l'action protégée depuis un compte nouvellement créé après chaque transition.
5. Ne vous arrêtez pas au bypass : si l'action modifie une ACL, accordez-vous des rôles persistants et appelez les APIs privilégiées normales.

Les schémas suspects comprennent `cachedSupply == balance`, `metadataOwner == caller` ou `snapshotShares == currentShares` lorsque les deux côtés suivent des règles de synchronisation différentes. Interroger une valeur faisant autorité pour un opérande ne rend pas la comparaison sûre lorsque l'autre opérande est obsolète.<sup>[[1]](#references)</sup>

## Bypass par égalité des valeurs par défaut

Un prédicat d'égalité est également dangereux lorsque les deux opérandes peuvent indépendamment prendre la même valeur par défaut. Le contrôle ci-dessous accorde le « contrôle de la totalité de l'offre » à tout compte vide lorsque `supply` vaut zéro, que ce zéro résulte de métadonnées obsolètes ou d'un objet légitimement non financé.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Le passage au canonical store corrige la divergence, mais **pas** le cas de l’objet vide. La propriété de sécurité doit inclure une condition de validité indépendante ; le patch Provenance utilise la supply actuelle de la banque et rejette une supply nil ou nulle avant de comparer le solde du caller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Appliquez le même raisonnement aux quorum counts, aux pourcentages de propriété, à la dette, aux collatéraux, aux epochs, aux nonces, aux timestamps et aux compteurs : `callerValue == protectedValue` ne doit pas autoriser un appelant tant que la valeur protégée n'est pas validée de manière indépendante et n'appartient pas au domaine attendu.<sup>[[1]](#references)</sup>

## Prise de contrôle de l'ACL menant à des opérations privilégiées légitimes

Un bypass dans une opération de modification de l'ACL constitue une primitive durable d'escalade de privilèges. Dans le cas de Provenance, un compte non privilégié ne possédant aucun token pouvait passer le test d'offre obsolète `0 == 0`, s'accorder à lui-même les permissions d'administration, de mint et de retrait, puis utiliser des message handlers ordinaires pour minter des assets ou retirer des fonds de l'escrow. L'exploit ne nécessitait donc aucune seconde vulnérabilité après la modification de l'ACL.<sup>[[1]](#references)</sup>

Séquence générale d'exploitation :<sup>[[1]](#references)</sup>

1. Trouver un objet dont un champ non authoritative diffère de l'état actuel, ou dont la valeur protégée est la valeur par défaut.
2. Utiliser une identité nouvelle/vide afin que sa valeur locale corresponde à cette valeur obsolète/par défaut.
3. Appeler l'endpoint de gestion des rôles, de transfert de propriété ou de mise à jour de la policy, puis s'accorder à soi-même des capabilities persistantes.
4. Confirmer la persistance en lisant l'ACL depuis l'état canonique.
5. Invoquer l'opération légitime à fort impact (mint, retrait, upgrade, transfert de propriété ou modification de la policy).

Lors de l'évaluation de l'impact, examinez chaque capability accessible depuis le nouveau rôle au lieu de vous arrêter au bypass d'autorisation. Les comptes de type escrow peuvent conserver des assets sans rapport avec l'objet dont les métadonnées obsolètes ont permis la prise de contrôle.<sup>[[1]](#references)</sup>

## Cibles pour les invariants et le stateful fuzzing

Spécifiez l'autorisation indépendamment de l'implémentation. Pour un raccourci reposant sur l'offre totale, l'invariant minimal est le suivant :<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Utilisez un fuzzer de state-machine pour générer des séquences — et non des appels isolés — couvrant la création, l'initialisation avec une valeur nulle, l'activation/finalisation, le minting, le burning, les transferts, les réinitialisations, les migrations, les appels de synchronisation et les changements d'ACL. Après chaque transition, comparez les représentations dupliquées et vérifiez qu'un compte nouvellement créé ne peut effectuer aucune action protégée. Ajoutez explicitement des cas pour les valeurs zéro, une unité, une propriété partielle, une propriété totale, une valeur obsolète inférieure et une valeur obsolète supérieure.<sup>[[1]](#references)[[2]](#references)</sup>

Les propriétés de régression à fort signal sont les suivantes :<sup>[[1]](#references)[[2]](#references)</sup>

- Une supply faisant autorité égale à zéro n'implique jamais la propriété ou l'administration.
- Les détenteurs partiels ne peuvent pas devenir administrateurs lorsqu'une supply dupliquée est égale à leur solde.
- Un détenteur réellement total conserve le raccourci prévu lorsque la supply live est positive.
- Les self-grants échoués ne modifient pas l'ACL et n'activent pas les appels privilégiés en aval.
- Les changements de mode ne peuvent pas modifier silencieusement la représentation qu'une vérification d'autorisation considère comme faisant autorité.

## References

- [1] [La divergence d'état permet un accès non autorisé (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Correction des vérifications de supply obsolètes](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit Provenance c81fd65 - Rejet d'une supply nulle dans le raccourci d'autorisation de la supply totale](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
