# ERC-4337 Smart Account Sekuriteitsvalstrikke

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 rekening-abstraksie verander wallets in programmeerbare stelsels. Die kernvloei is **validate-then-execute** oor 'n hele bundel: die `EntryPoint` valideer elke `UserOperation` voordat dit enigeen van hulle uitvoer. Hierdie ordening skep nie-voor-die-hand-liggende aanvalsvlak wanneer validasie permissief of staatvol is.

## 1) Direkte-aanroep om geprivilegieerde funksies te omseil
Enige van buite aanroepbare `execute` (of fonds-bewegende) funksie wat nie beperk is tot die `EntryPoint` (of 'n nagekeurde executor-module) nie, kan direk aangeroep word om die rekening leeg te trek.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Veilige patroon: beperk tot `EntryPoint`, en gebruik `msg.sender == address(this)` vir admin-/selfbestuursvloeie (module-installasie, validator-wisselings, opgraderings).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Ongetekende of onbeheerde gasvelde -> fooi-uitputting
As handtekeningverifikasie slegs die intentie (`callData`) dek maar nie gasverwante velde nie, kan `bundler` of `frontrunner` fooie opskroef en ETH leegtrek. Die ondertekende payload moet ten minste bind:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Verdedigingspatroon: gebruik die deur `EntryPoint` verskafde `userOpHash` (wat gasvelde insluit) en/of beperk elke veld streng.
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle semantics)
Omdat alle validerings voor enige uitvoering uitgevoer word, is dit onveilig om valideringsresultate in kontrakstaat te stoor. 'n Ander op in dieselfde bundel kan dit oor-skryf, wat veroorsaak dat jou uitvoering kwaadwillig beïnvloede staat gebruik.

Vermy om stoor te skryf in `validateUserOp`. As dit onvermydelik is, sleutel tydelike data met `userOpHash` en vee dit deterministies uit na gebruik (gebruik verkieslik staatlose validering).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` moet handtekenings bind aan **hierdie kontrak** en **hierdie ketting**. Recovering oor 'n rou hash laat handtekenings oor rekeninge of kettings herhaal.

Gebruik EIP-712 typed data (domein sluit `verifyingContract` en `chainId` in) en keer die presiese ERC-1271 magiese waarde `0x1626ba7e` terug by sukses.

## 5) Reverts do not refund after validation
Sodra `validateUserOp` slaag, word fooie toegeken selfs al revert die uitvoering later. Aanvallers kan herhaaldelik ops indien wat sal misluk en steeds fooie van die rekening invorder.

Vir paymasters is dit broos om uit 'n gedeelde poel te betaal in `validateUserOp` en gebruikers in `postOp` te belaas, omdat `postOp` kan revert sonder om die betaling ongedaan te maak. Beveilig fondse tydens validering (per-gebruiker escrow/deposit), en hou `postOp` minimaal en non-reverting.

## 6) ERC-7702 initialization frontrun
ERC-7702 laat 'n EOA toe om smart-account kode vir 'n enkele tx uit te voer. As initialization ekstern aanroepbaar is, kan 'n frontrunner homself as owner stel.

Mitigation: allow initialization only on **self-call** and only once.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vinnige kontrole voor samevoeging
- Valideer handtekeninge deur `EntryPoint` se `userOpHash` te gebruik (bind gasvelde).
- Beperk bevoorregte funksies tot `EntryPoint` en/of `address(this)` soos toepaslik.
- Hou `validateUserOp` staatloos.
- Dwing EIP-712 domeinseparasie af vir ERC-1271 en keer `0x1626ba7e` terug by sukses.
- Hou `postOp` minimaal, begrens en nie-terugdraaiend; beveilig fooie tydens validasie.
- Vir ERC-7702, staan init slegs toe by self-call en slegs een keer.

## Verwysings

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
