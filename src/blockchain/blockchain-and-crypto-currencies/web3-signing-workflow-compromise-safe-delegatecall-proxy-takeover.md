# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

'n Koue-beursie-diefstalketting het 'n **supply-chain compromise van die Safe{Wallet}-web-UI** gekombineer met 'n **on-chain delegatecall primitive wat 'n proxy se implementation pointer (slot 0) oorgeskryf het**. Die belangrikste gevolgtrekkings is:

- As 'n dApp kode in die signing path kan inject, kan dit 'n signer laat produseer 'n geldige **EIP-712 signature oor velde wat deur die aanvaller gekies is**, terwyl die oorspronklike UI-data herstel word sodat ander signers onbewus bly.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies stoor `masterCopy` (implementation) by **storage slot 0**. 'n Delegatecall na 'n contract wat na slot 0 skryf, “upgrade” die Safe effektief na attacker logic, wat volle beheer oor die wallet gee.<sup>[[3]](#references)</sup>

## Off-chain: Targeted signing mutation in Safe{Wallet}

'n Gepeuterde Safe bundle (`_app-*.js`) het spesifieke Safe- en signer-addresses selektief aangeval. Die injected logic is direk voor die signing call uitgevoer:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Aanvalseienskappe
- **Context-gated**: hard-coded allowlists vir slagoffer-Safes/signers het geraas voorkom en detection verlaag.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: velde (`to`, `data`, `operation`, gas) is onmiddellik voor `signTransaction` oorskryf en daarna teruggestel, sodat proposal payloads in die UI onskuldig gelyk het terwyl signatures met die attacker payload ooreengestem het.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets het structured data gewys, maar nie nested calldata gedecodeer of `operation = delegatecall` uitgelig nie, wat die gemuteerde message effektief blind-signed gemaak het.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevansie van Gateway validation
Safe proposals word na die **Safe Client Gateway** gestuur.<sup>[[5]](#references)</sup> Voor hardened checks kon die gateway ’n proposal aanvaar waar `safeTxHash`/signature met ander velde as dié in die JSON body ooreengestem het indien die UI dit ná signing herskryf het. Ná die incident verwerp die gateway nou proposals waarvan die hash/signature nie met die submitted transaction ooreenstem nie.<sup>[[3]](#references)</sup> Soortgelyke server-side hash verification moet op enige signing-orchestration API afgedwing word.

### Hoogtepunte van die 2025 Bybit/Safe incident
- Die Bybit cold-wallet drain op 21 Februarie 2025 (~401k ETH) het dieselfde patroon hergebruik: ’n compromised Safe S3 bundle het slegs vir Bybit signers geaktiveer en `operation=0` → `1` gewysig, met `to` wat na ’n pre-deployed attacker contract gewys het wat slot 0 skryf.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-gecachede `_app-52c9031bfa03da47.js` wys dat die logika op Bybit se Safe (`0x1db9…cf4`) en signer addresses gebaseer was, waarna dit onmiddellik ná execution na ’n clean bundle teruggerol is, wat die “mutate → sign → restore”-trick weerspieël.<sup>[[1]](#references)[[2]](#references)</sup>
- Die malicious contract (byvoorbeeld `0x9622…c7242`) het eenvoudige functions `sweepETH/sweepERC20` plus ’n `transfer(address,uint256)` bevat wat die implementation slot skryf. Execution van `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` het die proxy implementation verskuif en volledige beheer verleen.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies hou `masterCopy` by **storage slot 0** en delegate alle logika na dit. Omdat Safe **`operation = 1` (delegatecall)** ondersteun, kan enige signed transaction na ’n arbitrary contract wys en sy code in die proxy se storage context uitvoer.<sup>[[3]](#references)</sup>

’n Attacker contract het ’n ERC-20 `transfer(address,uint256)` nageboots, maar eerder `_to` in slot 0 geskryf:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Uitvoeringspad:<sup>[[1]](#references)[[3]](#references)</sup>
1. Slagoffers teken `execTransaction` met `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy valideer handtekeninge oor hierdie parameters.
3. Proxy gebruik `delegatecall` na `attackerContract`; die `transfer`-liggaam skryf slot 0.
4. Slot 0 (`masterCopy`) wys nou na aanvaller-beheerde logika → **volledige wallet-oorneming en dreinering van fondse**.

### Guard- en weergawe-aantekeninge (verharding ná die insident)
- Transaction guards is in Safe v1.3.0 bekendgestel en kan alle `execTransaction`-parameters voor uitvoering inspekteer; ’n guard kan `delegatecall` verwerp of beleid op die bestemming en calldata afdwing. Bybit het v1.1.1 gebruik, wat hierdie hook voorafgegaan het.<sup>[[2]](#references)[[6]](#references)</sup>

## Opsporing- en verhardingskontrolelys

- **UI-integriteit**: pin JS-assets / SRI; monitor bundelverskille; behandel die signing UI as deel van die vertrouensgrens.
- **Validasie tydens signing**: hardware wallets met **EIP-712 clear-signing**; wys `operation` eksplisiet en decode geneste calldata. Verwerp signing wanneer `operation = 1`, tensy beleid dit toelaat.<sup>[[3]](#references)</sup>
- **Bedienerkant-hashkontroles**: gateways/services wat proposals relê, moet `safeTxHash` herbereken en valideer dat handtekeninge ooreenstem met die ingediende velde.<sup>[[3]](#references)</sup>
- **Beleid/allowlists**: preflight-reëls vir `to`, selectors, asset-tipes, en verbied delegatecall behalwe vir gekeurde flows. Vereis ’n interne policy service voor volledig ondertekende transaksies uitgesaai word.
- **Contract-ontwerp**: vermy die blootstelling van arbitrêre delegatecall in multisig/treasury wallets, tensy dit streng nodig is. Behandel enige implementation pointer as ’n upgrade primitive: beskerm dit met eksplisiete access control en guard delegatecall-teikens/selectors; om die pointer alleen na ’n ander slot te verskuif, is nie ’n volledige verdediging nie.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitering**: waarsku oor delegatecall-uitvoerings vanaf wallets wat treasury-fondse hou, en oor proposals wat `operation` vanaf tipiese `call`-patrone verander.

## References

- [1] [AnChain.AI forensiese ontleding van die Bybit Safe-exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology se ontleding van die Safe-bundelkompromittering](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-diepte tegniese ontleding van die Bybit-hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0-veranderingslog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
