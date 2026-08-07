# ERC-4337-sekuriteitsvalstrikke vir Smart Accounts

{{#include ../../banners/hacktricks-training.md}}

ERC-4337-account abstraction verander wallets in programmeerbare stelsels. Die kernvloei is **validate-then-execute** oor ’n hele bundle: die `EntryPoint` valideer elke `UserOperation` voordat enige daarvan uitgevoer word. Hierdie volgorde skep ’n nie-ooglopende attack surface wanneer validation permissief, stateful of inkonsekwent met bundler-simulasie-reëls is.

## 1) Direct-call-bypass van bevoorregte funksies
Enige ekstern oproepbare `execute`- (of fondsverskuiwende) funksie wat nie tot `EntryPoint` (of ’n gekeurde executor module) beperk is nie, kan direk opgeroep word om die account te dreineer.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Veilige patroon: beperk tot `EntryPoint`, en gebruik `msg.sender == address(this)` vir admin/self-management-vloeie (module-installering, validator-veranderinge, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Ongesignede of ongekontroleerde gas fields -> fee drain
Indien signature validation slegs intent (`callData`) dek, maar nie gas-related fields nie, kan ’n bundler of frontrunner fees opjaag en ETH dreineer. Die signed payload moet ten minste die volgende bind:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: gebruik die `EntryPoint`-verskafde `userOpHash` (wat gas fields insluit) en/of stel streng limiete vir elke field.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (bundle-semantiek)
Omdat alle validasies voor enige uitvoering plaasvind, is dit onveilig om validasieresultate in contractstaat te stoor. Nog ’n op in dieselfde bundle kan dit oorskryf, wat veroorsaak dat jou uitvoering aanvaller-beïnvloede staat gebruik.<sup>[[1]](#references)</sup>

Vermy die skryf van storage in `validateUserOp`. Indien dit onvermydelik is, sleutel tydelike data volgens `userOpHash` en verwyder dit deterministies ná gebruik (verkies stateless validation).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (ontbrekende domeinskeiding)
`isValidSignature(bytes32 hash, bytes sig)` moet handtekeninge aan **hierdie kontrak** en **hierdie chain** bind. As oor ’n raw hash herstel word, kan handtekeninge oor accounts of chains heen hergebruik word.<sup>[[1]](#references)</sup>

Gebruik EIP-712 typed data (die domain sluit `verifyingContract` en `chainId` in) en gee die presiese ERC-1271 magic value `0x1626ba7e` terug by sukses.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
Sodra `validateUserOp` slaag, is fooie verbind, selfs al revert uitvoering later. Aanvallers kan herhaaldelik ops indien wat sal misluk en steeds fooie uit die account invorder.<sup>[[1]](#references)</sup>

Vir paymasters is dit broos om tydens `validateUserOp` uit ’n shared pool te betaal en gebruikers in `postOp` te hef, omdat `postOp` kan revert sonder om die betaling ongedaan te maak. Beveilig fondse tydens validasie (per-user escrow/deposit), hou `postOp` minimaal en nie-reverterend, en begroot `paymasterPostOpGasLimit` vir die worst-case reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory-aannames
Die eerste `UserOperation` bevat dikwels `initCode`, wat veroorsaak dat die account tydens validasie deur ’n **factory** gedeploy word. Hierdie pad word maklik onvoldoende geoudit omdat dit slegs tydens die eerste gebruik loop.<sup>[[2]](#references)</sup>

Algemene foute:

- Die factory/initializer vertrou `msg.sender == entryPoint`, maar die ERC-4337 deployment path roep **nie** `initCode` direk vanaf `EntryPoint` aan nie.
- Die salt, owner, validator of module-konfigurasie is nie volledig aan signed intent gebind nie, sodat ’n frontrunner die eerste deployment kan jaag en die counterfactual address met aanvaller-beheerde settings kan beset.
- Die factory is nie-idempotent, sodat ’n herhaalde first-use flow die wallet blokkeer in plaas daarvan om die reeds-geskepte address terug te gee.

Veilige patroon: bereken die verwagte sender weer uit signed deployment parameters, maak deployment deterministies (tipies `CREATE2`), en maak initialisering eenmalig.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation-logika wat bundlers reject
Validation-kode kan korrek wees in plaaslike toetse en steeds onbruikbaar wees in werklike bundlers. Publieke bundlers simuleer `validateUserOp()` / `validatePaymasterUserOp()` off-chain en voer gewoonlik ’n volledige `debug_traceCall(handleOps)` uit voordat dit ingesluit word.

Dit maak hierdie patrone binne validation gevaarlik:

- Blokafhanklike opcodes soos `TIMESTAMP`, `NUMBER` of `BLOCKHASH`
- State writes soos `SSTORE`
- Onbeperkte iterasie oor storage
- Arbitrêre eksterne calls of oracle reads wat tussen simulasie en insluiting kan verander

Slegte voorbeeld:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Behandel validation as ’n deterministiese, begrensde preflight-funksie. Indien jy werklik gedeelde toestand of eksterne lookups benodig, skuif daardie kompleksiteit na entities wat gestake en reputasie-nagespoor word, en toets die presiese bundler-simulasiepad, nie net unit tests nie.

## 8) ERC-7702 initialization frontrun
ERC-7702 laat ’n EOA toe om smart-account-kode vir ’n enkele tx uit te voer. Indien initialization externally callable is, kan ’n frontrunner hulself as owner instel.<sup>[[1]](#references)</sup>

Mitigation: laat initialization slegs op **self-call** en slegs een keer toe.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vinnige pre-merge-kontroles
- Valideer handtekeninge met `EntryPoint` se `userOpHash` (bind gas-velde).
- Beperk bevoorregte funksies tot `EntryPoint` en/of `address(this)` soos toepaslik.
- Hou `validateUserOp` stateless, deterministies en versoenbaar met bundler-simulasie-reëls.
- Dwing EIP-712-domeinskeiding vir ERC-1271 af en gee `0x1626ba7e` terug by sukses.
- Hou `postOp` minimaal, begrens en nie-reverterend; beveilig fooie tydens validasie.
- Toets die eerste `initCode`-pad afsonderlik: deterministiese deployment, idempotente factory-gedrag en eenmalige initialisering.
- Voer volledige bundler-simulasie uit (`simulateValidation` plus ’n traced `handleOps`) voordat dit vrygestel word.
- Vir ERC-7702, laat init slegs op self-call en slegs een keer toe.



## Verwysings

- [1] [Ses foute in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Rekeningabstraksie met Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
