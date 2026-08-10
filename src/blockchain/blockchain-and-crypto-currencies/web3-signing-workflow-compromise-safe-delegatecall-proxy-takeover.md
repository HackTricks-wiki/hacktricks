# Compromission du workflow de signature Web3 et prise de contrôle d’un proxy Safe Delegatecall

## Overview

Une chaîne de vol depuis un cold wallet a combiné une **compromission de la supply chain de l’interface web Safe{Wallet}** avec une **primitive on-chain delegatecall qui écrasait le pointeur d’implémentation d’un proxy (slot 0)**. Les principaux enseignements sont les suivants :

- Si une dApp peut injecter du code dans le workflow de signature, elle peut faire produire à un signer une **signature EIP-712 valide portant sur des champs choisis par l’attaquant**, tout en restaurant les données originales de l’interface afin que les autres signers ne se doutent de rien.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Les proxies Safe stockent `masterCopy` (l’implémentation) dans le **storage slot 0**. Un delegatecall vers un contract qui écrit dans le slot 0 « met effectivement à niveau » le Safe vers la logique de l’attaquant, ce qui donne le contrôle total du wallet.<sup>[[3]](#references)</sup>

## Off-chain : mutation ciblée de la signature dans Safe{Wallet}

Un bundle Safe altéré (`_app-*.js`) ciblait sélectivement certaines adresses Safe + signer. La logique injectée s’exécutait juste avant l’appel de signature :<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated** : des allowlists codées en dur pour les Safe/signers victimes ont empêché le bruit et réduit la détection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutation au dernier moment** : les champs (`to`, `data`, `operation`, gas) étaient écrasés immédiatement avant `signTransaction`, puis restaurés, de sorte que les payloads de proposition dans l’interface semblaient bénins tandis que les signatures correspondaient au payload de l’attaquant.<sup>[[3]](#references)</sup>
- **Opacité d’EIP-712** : les wallets affichaient des données structurées, mais ne décodaient pas les calldata imbriqués et ne mettaient pas en évidence `operation = delegatecall`, ce qui rendait le message modifié effectivement blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Pertinence de la validation du Gateway
Les propositions Safe sont soumises au **Safe Client Gateway**.<sup>[[5]](#references)</sup> Avant le renforcement des contrôles, le Gateway pouvait accepter une proposition dont le `safeTxHash`/la signature correspondait à des champs différents de ceux du corps JSON si l’interface les réécrivait après la signature. Après l’incident, le Gateway rejette désormais les propositions dont le hash/la signature ne correspondent pas à la transaction soumise.<sup>[[3]](#references)</sup> Une vérification côté serveur similaire du hash devrait être appliquée à toute API d’orchestration de signature.

### Points clés de l’incident Bybit/Safe de 2025
- Le drainage du cold wallet de Bybit du 21 février 2025 (environ 401k ETH) a réutilisé le même schéma : un bundle S3 Safe compromis ne se déclenchait que pour les signers de Bybit et remplaçait `operation=0` par `1`, en faisant pointer `to` vers un contrat de l’attaquant pré-déployé qui écrivait dans le slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js`, mis en cache par Wayback, montre une logique basée sur le Safe de Bybit (`0x1db9…cf4`) et les adresses des signers, puis immédiatement restaurée vers un bundle propre deux minutes après l’exécution, reproduisant l’astuce « mutate → sign → restore ».<sup>[[1]](#references)[[2]](#references)</sup>
- Le contrat malveillant (par exemple `0x9622…c7242`) contenait des fonctions simples `sweepETH/sweepERC20` ainsi qu’une fonction `transfer(address,uint256)` qui écrivait dans le slot d’implémentation. L’exécution de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` a modifié l’implémentation du proxy et accordé un contrôle total.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain : prise de contrôle d’un proxy Delegatecall via collision de slots

Les proxies Safe stockent `masterCopy` dans le **storage slot 0** et délèguent toute la logique à celui-ci. Comme Safe prend en charge **`operation = 1` (delegatecall)**, toute transaction signée peut pointer vers un contrat arbitraire et exécuter son code dans le contexte de stockage du proxy.<sup>[[3]](#references)</sup>

Un contrat de l’attaquant imitait un `transfer(address,uint256)` ERC-20, mais écrivait à la place `_to` dans le slot 0 :<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Chemin d’exécution :<sup>[[1]](#references)[[3]](#references)</sup>
1. Les victimes signent `execTransaction` avec `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Le masterCopy de Safe valide les signatures sur ces paramètres.
3. Le Proxy effectue un delegatecall vers `attackerContract` ; le corps de `transfer` écrit dans le slot 0.
4. Le slot 0 (`masterCopy`) pointe désormais vers une logique contrôlée par l’attaquant → **prise de contrôle complète du wallet et drainage des fonds**.

### Notes sur le Guard et la version (durcissement post-incident)
- Les transaction guards ont été introduits dans Safe v1.3.0 et peuvent inspecter tous les paramètres de `execTransaction` avant l’exécution ; un guard peut rejeter `delegatecall` ou appliquer une policy sur la destination et le calldata. Bybit utilisait la v1.1.1, antérieure à ce hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Liste de contrôle de détection et de durcissement

- **Intégrité de l’UI** : épingler les assets JS / SRI ; surveiller les différences entre bundles ; considérer l’UI de signature comme faisant partie de la trust boundary.
- **Validation au moment de la signature** : hardware wallets avec **EIP-712 clear-signing** ; afficher explicitement `operation` et décoder le calldata imbriqué. Refuser la signature lorsque `operation = 1`, sauf si la policy l’autorise.<sup>[[3]](#references)</sup>
- **Vérifications des hashes côté serveur** : les gateways/services qui relaient les proposals doivent recalculer `safeTxHash` et vérifier que les signatures correspondent aux champs soumis.<sup>[[3]](#references)</sup>
- **Policy/allowlists** : règles de preflight pour `to`, les selectors et les types d’assets, et interdire delegatecall sauf pour les flows vérifiés. Exiger un service de policy interne avant de broadcaster des transactions entièrement signées.
- **Conception des contrats** : éviter d’exposer un delegatecall arbitraire dans les wallets multisig/treasury, sauf nécessité stricte. Traiter tout pointeur d’implementation comme une primitive d’upgrade : le protéger avec un contrôle d’accès explicite et contrôler les cibles/selectors de delegatecall ; déplacer uniquement le pointeur vers un autre slot ne constitue pas une défense complète.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring** : déclencher une alerte lors des exécutions de delegatecall depuis des wallets détenant des fonds de treasury, ainsi que pour les proposals qui modifient `operation` par rapport aux patterns habituels de `call`.

## References

- [1] [Analyse forensic de l’exploit du Safe de Bybit par AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analyse de la compromission du bundle Safe par Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Analyse technique approfondie du hack de Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Journal des modifications de Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
