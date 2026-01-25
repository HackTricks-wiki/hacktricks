# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

A cold-wallet theft chain combined a **voorsieningsketting-kompromie van die Safe{Wallet} web UI** met 'n **on-chain delegatecall primitive wat 'n proxy se implementasie-aanwyser (slot 0) oor geskryf het**. Die belangrikste afleidings is:

- If a dApp can inject code into the signing path, it can make a signer produce a valid **EIP-712 signature over attacker-chosen fields** while restoring the original UI data so other signers remain unaware.
- Safe proxies store `masterCopy` (implementation) at **storage slot 0**. A delegatecall to a contract that writes to slot 0 effectively “upgrades” the Safe to attacker logic, yielding full control of the wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

'n Gemanipuleerde Safe bundle (`_app-*.js`) het selektief spesifieke Safe + ondertekenaar-adresse geteiken. Die ingesette logika het uitgevoer reg voor die ondertekeningsoproep:
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
- **Context-gated**: hard-coded allowlists vir slagoffer Safes/signers het geraas verhoed en opsporing verlaag.
- **Last-moment mutation**: velde (`to`, `data`, `operation`, gas) is onmiddellik voor `signTransaction` oorskryf en daarna teruggedraai, sodat voorstel-payloads in die UI onskuldig gelyk het terwyl handtekeninge by die aanvaller-payload gepas het.
- **EIP-712 opacity**: wallets het gestruktureerde data gewys maar het nie nested calldata ontleed of `operation = delegatecall` uitgelig nie, wat die gemuteerde boodskap effektief blind geteken het.

### Gateway validation relevance
Safe-proposals word ingedien by die **Safe Client Gateway**. Voor die verskerpte kontroles kon die gateway ’n voorstel aanvaar waar `safeTxHash`/handtekening ooreengestem het met ander velde as die JSON-lyf indien die UI hulle ná ondertekening herskryf het. Na die insident verwerp die gateway nou voorstelle waarvan die hash/handtekening nie met die ingediende transaksie ooreenstem nie. Vergelykbare server-side hash-verifikasie moet op enige signing-orchestration API afgedwing word.

### 2025 Bybit/Safe incident highlights
- Die 21 Februarie 2025 Bybit cold-wallet onttrekking (~401k ETH) hergebruik die selfde patroon: ’n gekompromitteerde Safe S3 bundle het slegs vir Bybit signers getrigger en het `operation=0` → `1` verwissel, en `to` gerig na ’n vooraf gedeployde attacker contract wat slot 0 skryf.
- Wayback-cached `_app-52c9031bfa03da47.js` toon die logika gesleutel op Bybit’s Safe (`0x1db9…cf4`) en signer adresse, en is dan onmiddellik twee minute ná uitvoering teruggerol na ’n skoon bundle, wat die “mutate → sign → restore” truuk weerspieël.
- Die kwaadwillige kontrak (bv. `0x9622…c7242`) het eenvoudige funksies `sweepETH/sweepERC20` bevat plus ’n `transfer(address,uint256)` wat die implementation slot skryf. Uitvoering van `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` het die proxy-implementasie verskuif en volle beheer gegee.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies hou `masterCopy` by **storage slot 0** en delegeer alle logika daarnaar. Omdat Safe **`operation = 1` (delegatecall)** ondersteun, kan enige ondertekende transaksie na ’n arbitrêre kontrak wys en sy kode in die proxy se stoor-konteks uitvoer.

’n attacker contract het ’n ERC-20 `transfer(address,uint256)` nageboots maar in plaas daarvan `_to` in slot 0 geskryf:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Uitvoeringspad:
1. Slagoffers teken `execTransaction` met `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy valideer handtekeninge oor hierdie parameters.
3. Proxy voer delegatecall uit na `attackerContract`; die `transfer`-liggaam skryf na slot 0.
4. Slot 0 (`masterCopy`) verwys nou na aanvaller-gekontroleerde logika → **volledige wallet-oorgreep en fondsonttrekking**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 kan installeer ’n **Guard** om `delegatecall` te veto of ACLs op `to`/selectors af te dwing; Bybit het v1.1.1 gebruik, so geen Guard-hook bestaan nie. Om hierdie beheerlaag te verkry, is dit nodig om kontrakte op te gradeer (en eienaars weer by te voeg).

## Opsporing & verhardingskontrolelys

- **UI integrity**: pin JS assets / SRI; monitor bundle diffs; behandel signing UI as deel van die trust boundary.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; render `operation` eksplisiet en decode nested calldata. Weier ondertekening wanneer `operation = 1` tensy beleid dit toelaat.
- **Server-side hash checks**: gateways/services wat voorstelle deurstuur, moet `safeTxHash` herbereken en valideer dat handtekeninge ooreenstem met die ingediende velde.
- **Policy/allowlists**: preflight rules vir `to`, selectors, asset tipes, en verbied delegatecall behalwe vir vetted flows. Vereis ’n interne policy service voordat volledig getekende transaksies uitgesaai word.
- **Contract design**: vermy die blootstelling van arbitrêre delegatecall in multisig/treasury wallets tensy dit strikt noodsaaklik is. Plaas upgrade pointers weg van slot 0 of beveilig met eksplisiete opgraderingslogika en toegangbeheer.
- **Monitoring**: waarsku op delegatecall-uitvoerings van wallets wat treasury-fondse hou, en op voorstelle wat `operation` verander van tipiese `call`-patrone.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
