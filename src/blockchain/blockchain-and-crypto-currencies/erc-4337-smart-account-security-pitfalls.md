# ERC-4337 Slimrekening-sekuriteitsvalkuilen

{{#include ../../banners/hacktricks-training.md}}

ERC-4337-rekeningabstraksie verander wallets in programmeerbare stelsels. Die kernvloei is **validate-then-execute** oor ’n hele bundel: die `EntryPoint` valideer elke `UserOperation` voordat enige daarvan uitgevoer word. Hierdie volgorde skep nie-vanselfsprekende aanvaloppervlak wanneer validering permissief, toestandsafhanklik of inkonsekwent met bundler-simulasie-reëls is.

## 1) Omseiling van toegangsbeheer vir bevoorregte funksies deur direkte oproepe
Enige ekstern-aanroepbare `execute`- (of fondseverskuiwende) funksie wat nie tot `EntryPoint` (of ’n gekeurde uitvoerdermodule) beperk is nie, kan direk aangeroep word om die rekening leeg te trek.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Veilige patroon: beperk dit tot `EntryPoint`, en gebruik `msg.sender == address(this)` vir administrasie-/selfbestuurvloeie (module-installering, validatorveranderings, opgraderings).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Ongesignerde of ongekontroleerde gas-velde -> fooiaftapping
As handtekeningvalidasie slegs die intent (`callData`) dek, maar nie gasverwante velde nie, kan ’n bundler of frontrunner fooie opblaas en ETH tap. Die signed payload moet aan minstens die volgende bind:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: gebruik die `EntryPoint`-verskafte `userOpHash` (wat gas-velde insluit) en/of stel streng limiete vir elke veld.<sup>[[1]](#references)</sup>
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
Omdat alle validasies voor enige uitvoering plaasvind, is dit onveilig om validasier resultate in contract state te stoor. Nog ’n op in dieselfde bundle kan dit oorskryf, wat veroorsaak dat jou uitvoering attacker-beïnvloede state gebruik.<sup>[[1]](#references)</sup>

Vermy die skryf van storage in `validateUserOp`. Indien dit onvermydelik is, sleutel tydelike data volgens `userOpHash` en verwyder dit deterministies ná gebruik (verkies stateless validation).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay oor accounts/chains (ontbrekende domain separation)
`isValidSignature(bytes32 hash, bytes sig)` moet handtekeninge aan **hierdie contract** en **hierdie chain** bind. Herwinning oor ’n raw hash laat handtekeninge toe om oor accounts of chains gereplay te word.<sup>[[1]](#references)</sup>

Gebruik EIP-712 typed data (domain sluit `verifyingContract` en `chainId` in) en stuur die presiese ERC-1271 magic value `0x1626ba7e` terug by sukses.<sup>[[1]](#references)</sup>

## 5) Reverts refund nie ná validation nie
Sodra `validateUserOp` suksesvol is, is fees verbind, selfs al revert uitvoering later. Attackers kan herhaaldelik ops indien wat sal fail en steeds fees van die account invorder.<sup>[[1]](#references)</sup>

Vir paymasters is betaling uit ’n shared pool in `validateUserOp` en die charging van users in `postOp` riskant, omdat `postOp` kan revert sonder om die betaling ongedaan te maak. Beveilig funds tydens validation (per-user escrow/deposit), hou `postOp` minimaal en non-reverting, en begroot `paymasterPostOpGasLimit` vir die worst-case reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory-aannames
Die eerste `UserOperation` bevat dikwels `initCode`, wat veroorsaak dat die account tydens validation deur ’n **factory** gedeploy word. Hierdie path word maklik onvoldoende geoudit omdat dit slegs met eerste gebruik loop.<sup>[[2]](#references)</sup>

Algemene failures:

- Die factory/initializer vertrou `msg.sender == entryPoint`, maar die ERC-4337 deployment path roep **nie** `initCode` direk vanaf `EntryPoint` aan nie.
- Die salt, owner, validator of module-konfigurasie is nie volledig aan signed intent gebind nie, dus kan ’n frontrunner die eerste deployment race en die counterfactual address met attacker-beheerde settings burn.
- Die factory is non-idempotent, dus maak ’n herhaalde first-use flow die wallet onbruikbaar in plaas daarvan om die reeds geskepte address terug te stuur.

Veilige patroon: bereken die verwagte sender opnieuw uit signed deployment parameters, maak deployment deterministies (tipies `CREATE2`), en maak initialization eenmalig.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic wat bundlers verwerp
Validation-kode kan korrek wees in plaaslike toetse en steeds onbruikbaar wees in werklike bundlers. Publieke bundlers simuleer `validateUserOp()` / `validatePaymasterUserOp()` off-chain en voer algemeen ’n volledige `debug_traceCall(handleOps)` uit vóór inclusion.<sup>[[3]](#references)</sup>

Dit maak hierdie patrone binne validation gevaarlik:

- Block-dependent opcodes soos `TIMESTAMP`, `NUMBER` of `BLOCKHASH`
- State writes soos `SSTORE`
- Onbegrensde iterasie oor storage
- Arbitrêre external calls of oracle reads wat tussen simulation en inclusion kan verander

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
Behandel validasie as ’n deterministiese, begrensde preflight-funksie. As jy werklik gedeelde toestand of eksterne opsoeke benodig, skuif daardie kompleksiteit na gestakede/reputasie-nagespoorde entiteite en toets die presiese bundler-simulasiepad, nie net unit tests nie.

## 8) ERC-7702 initialization frontrun
ERC-7702 laat ’n EOA toe om smart-account-kode vir ’n enkele tx uit te voer. As initialisering ekstern oproepbaar is, kan ’n frontrunner hulself as die eienaar instel.<sup>[[1]](#references)</sup>

Versagting: laat initialisering slegs op **self-call** en slegs een keer toe.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Vinnige pre-merge checks
- Valideer handtekeninge met `EntryPoint` se `userOpHash` (bind gas-velde).
- Beperk bevoorregte funksies tot `EntryPoint` en/of `address(this)` soos toepaslik.
- Hou `validateUserOp` stateless, deterministies en versoenbaar met bundler-simulasie-reëls.
- Dwing EIP-712-domeinskeiding af vir ERC-1271 en gee `0x1626ba7e` terug by sukses.
- Hou `postOp` minimaal, begrens en nie-reverterend; beveilig fooie tydens validasie.
- Toets die eerste `initCode`-pad afsonderlik: deterministiese deployment, idempotente factory-gedrag en eenmalige initialisering.
- Voer volledige bundler-simulasie uit (`simulateValidation` plus ’n traced `handleOps`) voordat dit vrygestel word.
- Vir ERC-7702, laat init slegs op self-call toe en slegs een keer.

## Verwysings

- [1] [Ses foute in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
