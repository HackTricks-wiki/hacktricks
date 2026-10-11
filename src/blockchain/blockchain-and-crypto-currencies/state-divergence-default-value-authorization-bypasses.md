# Divergence d’état et contournements d’autorisation par valeur par défaut

{{#include ../../banners/hacktricks-training.md}}

L’autorisation dépend parfois d’un état économique dérivé plutôt que d’un rôle explicite — par exemple, « l’appelant possède la totalité de l’offre ». Si les valeurs de ce prédicat proviennent de différents stockages, une copie obsolète peut transformer un raccourci légitime fondé sur la propriété en contournement d’autorisation. Le module Provenance marker a montré la combinaison dangereuse : un solde actuel de l’appelant était comparé aux métadonnées locales du marqueur concernant l’offre, qui n’étaient pas mises à jour pour les actifs à offre non fixe.<sup>[[1]](#references)</sup>

## Auditer les états dupliqués qui servent de frontière d’autorisation

Pour chaque valeur utilisée dans une vérification des permissions, répertoriez **toutes les représentations** : état canonique du module, champs d’objet, agrégats mis en cache, index, instantanés, enregistrements de bridge et copies miroir hors chaîne. Retracez ensuite chaque chemin de création, de mint, de burn, de transfert, de réinitialisation, de migration et de synchronisation afin de déterminer quelle copie est mise à jour dans chaque mode d’objet. Un champ peut faire autorité dans un mode et être uniquement informatif dans un autre.<sup>[[1]](#references)</sup>

Voici une méthode pratique d’audit :<sup>[[1]](#references)</sup>

1. Repérez les actions protégées et réduisez chaque branche d’autorisation à un prédicat booléen.
2. Pour chaque opérande, consignez son stockage, ses chemins de mise à jour, ses états de cycle de vie et sa source de vérité.
3. Générez des transitions qui ne mettent à jour qu’une seule représentation, puis comparez toutes les copies.
4. Après chaque transition, tentez l’action protégée depuis un compte vierge.
5. Ne vous arrêtez pas au contournement : si l’action modifie une ACL, attribuez-vous des rôles persistants, puis appelez les API privilégiées habituelles.

Les schémas suspects comprennent `cachedSupply == balance`, `metadataOwner == caller` ou `snapshotShares == currentShares` lorsque les deux côtés suivent des règles de synchronisation différentes. Interroger une valeur faisant autorité pour un opérande ne rend pas la comparaison sûre si l’autre opérande est obsolète.<sup>[[1]](#references)</sup>

## Contournement par égalité avec une valeur par défaut

Un prédicat d’égalité est également dangereux lorsque les deux opérandes peuvent indépendamment prendre la même valeur par défaut. La vérification ci-dessous accorde le « contrôle total de l’offre » à tout compte vide lorsque `supply` vaut zéro, que ce zéro provienne de métadonnées obsolètes ou d’un objet légitimement non financé.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Passer au stockage canonique corrige la divergence, mais **pas** le cas de l’objet vide. La propriété de sécurité doit inclure une condition de validité indépendante ; le patch Provenance utilise l’offre actuelle de la banque et rejette une offre nulle ou égale à zéro avant de comparer le solde de l’appelant.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Appliquez le même raisonnement aux nombres de voix nécessaires pour atteindre le quorum, aux pourcentages de propriété, aux dettes, aux garanties, aux époques, aux nonces, aux horodatages et aux compteurs : `callerValue == protectedValue` ne doit pas autoriser un appelant tant que la valeur protégée n’est pas valide de manière indépendante et n’appartient pas au domaine attendu.<sup>[[1]](#references)</sup>

## Prise de contrôle de l’ACL menant à des opérations privilégiées légitimes

Un contournement dans une opération de modification de l’ACL constitue un moyen durable d’escalade de privilèges. Dans le cas de Provenance, un compte non privilégié sans jetons pouvait réussir le test d’offre obsolète `0 == 0`, s’accorder des permissions d’administration, de création de jetons et de retrait, puis utiliser les gestionnaires de messages ordinaires pour créer des actifs ou retirer des fonds sous séquestre. L’exploitation ne nécessitait donc aucune autre vulnérabilité après la modification de l’ACL.<sup>[[1]](#references)</sup>

Séquence générale d’exploitation :<sup>[[1]](#references)</sup>

1. Trouvez un objet dont un champ non fiable diffère de l’état actuel, ou dont la valeur protégée est la valeur par défaut.
2. Utilisez une identité nouvelle ou vide afin que sa valeur locale corresponde à cette valeur obsolète ou par défaut.
3. Appelez le point de terminaison de gestion des rôles, de transfert de propriété ou de mise à jour des politiques et accordez-vous des capacités durables.
4. Vérifiez la persistance en lisant l’ACL dans l’état canonique.
5. Appelez l’opération légitime à fort impact (créer des jetons, retirer des fonds, mettre à niveau, transférer la propriété ou modifier une politique).

Lors de l’évaluation de l’impact, examinez toutes les capacités accessibles depuis le nouveau rôle au lieu de vous arrêter au contournement de l’autorisation. Les comptes de type séquestre peuvent détenir des actifs sans rapport avec l’objet dont les métadonnées obsolètes ont permis la prise de contrôle.<sup>[[1]](#references)</sup>

## Cibles pour les invariants et le fuzzing avec état

Définissez l’autorisation indépendamment de l’implémentation. Pour un raccourci fondé sur l’offre totale, l’invariant minimal est :<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Utilisez un fuzzer de modèle/machine à états pour générer des séquences — et non des appels isolés — couvrant la création, l’initialisation à zéro, l’activation/la finalisation, la frappe, le brûlage, les transferts, les réinitialisations, les migrations, les appels sync et les modifications de l’ACL. Après chaque transition, comparez les représentations dupliquées et vérifiez qu’un compte nouvellement créé ne peut effectuer aucune action protégée. Ajoutez des cas explicites pour les valeurs zéro, une unité, la propriété partielle, la propriété totale, les valeurs périmées trop faibles et les valeurs périmées trop élevées.<sup>[[1]](#references)[[2]](#references)</sup>

Les propriétés de régression les plus révélatrices sont :<sup>[[1]](#references)[[2]](#references)</sup>

- Une offre faisant autorité égale à zéro ne confère jamais de propriété ni de droits d’administration.
- Les détenteurs partiels ne peuvent pas devenir administrateurs lorsque l’offre dupliquée est égale à leur solde.
- Un véritable détenteur de la totalité conserve le raccourci prévu lorsque l’offre actuelle est positive.
- Les tentatives infructueuses de s’octroyer des droits ne modifient pas l’ACL et n’activent pas d’appels privilégiés en aval.
- Les changements de mode ne peuvent pas modifier silencieusement la représentation qu’un contrôle d’autorisation considère comme faisant autorité.

## References

- [1] [La divergence d’état permet un accès non autorisé (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Corriger les vérifications d’offre périmées](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit Provenance c81fd65 - Rejeter une offre nulle dans le raccourci d’autorisation basé sur l’offre totale](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
