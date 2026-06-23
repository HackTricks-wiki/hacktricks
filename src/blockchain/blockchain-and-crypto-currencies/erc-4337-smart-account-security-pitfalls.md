# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction verander wallets in programmeerbare stelsels. Die kernvloei is **validate-then-execute** oor 'n hele bundle: die `EntryPoint` valideer elke `UserOperation` voordat enige van hulle uitgevoer word. Hierdie ordening skep nie-ooglopende aanvaloppervlak wanneer validation permissief, stateful, of inkonsekwent met bundler simulation rules is.

## 1) Direct-call bypass of privileged functions
Enige externally callable `execute` (of fund-moving) function wat nie beperk is tot `EntryPoint` nie (of 'n vetted executor module) kan direk geroep word om die account leeg te dreineer.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Veilige patroon: beperk tot `EntryPoint`, en gebruik `msg.sender == address(this)` vir admin/self-management-vloei (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Ongesigne of ongekontroleerde gas-velde -> fooi-uitputting
As signature validation slegs intent (`callData`) dek maar nie gas-verwante velde nie, kan ’n bundler of frontrunner fooie opblaas en ETH dreineer. Die gesigneerde payload moet ten minste bind:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: gebruik die `EntryPoint`-verskafde `userOpHash` (wat gas-velde insluit) en/of beperk elke veld streng.
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
Omdat alle validations voor enige execution loop, is die stoor van validation results in contract state onveilig. Nog `n op in dieselfde bundle kan dit oorskryf, wat veroorsaak dat jou execution staat gebruik wat deur die attacker beïnvloed is.

Vermy om storage in `validateUserOp` te skryf. As dit onvermydelik is, key tydelike data by `userOpHash` en delete dit deterministies na gebruik (verkies stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` moet signatures bind aan **hierdie contract** en **hierdie chain**. Recovering oor `n rou hash laat signatures replay across accounts of chains.

Gebruik EIP-712 typed data (domain sluit `verifyingContract` en `chainId` in) en return die presiese ERC-1271 magic value `0x1626ba7e` by sukses.

## 5) Reverts do not refund after validation
Sodra `validateUserOp` slaag, is fees committed selfs al revert execution later. Attackers kan herhaaldelik ops submit wat sal fail en steeds fees van die account collect.

Vir paymasters, om from `n shared pool in `validateUserOp` te betaal en users in `postOp` te charge is fragiel omdat `postOp` kan revert sonder om die payment undo. Secure funds during validation (per-user escrow/deposit), keep `postOp` minimal en non-reverting, en budget `paymasterPostOpGasLimit` vir die worst-case reimbursement path.

## 6) Counterfactual deployment / factory assumptions
Die eerste `UserOperation` dra dikwels `initCode`, wat veroorsaak dat die account deur `n **factory** during validation gedeploy word. Hierdie path is maklik om under-audit te wees omdat dit slegs op eerste gebruik loop.

Common failures:

- Die factory/initializer trust `msg.sender == entryPoint`, maar die ERC-4337 deployment path roep nie `initCode` direk van `EntryPoint` af nie.
- Die salt, owner, validator, of module configuration is nie volledig gebind aan signed intent nie, so `n frontrunner kan die eerste deployment race en die counterfactual address met attacker-controlled settings burn.
- Die factory is non-idempotent, so `n herhaalde first-use flow bricked die wallet in plaas daarvan om die reeds-created address terug te gee.

Safe pattern: recompute the expected sender from signed deployment parameters, maak deployment deterministic (tipies `CREATE2`), en maak initialization one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic that bundlers reject
Validasielogika kan korrek wees in plaaslike toetse en steeds onbruikbaar wees in werklike bundlers. Publieke bundlers simuleer `validateUserOp()` / `validatePaymasterUserOp()` off-chain en voer gewoonlik `debug_traceCall(handleOps)` volledig uit voordat dit ingesluit word.

Dit maak hierdie patrone gevaarlik binne validasie:

- Block-afhanklike opcodes soos `TIMESTAMP`, `NUMBER`, of `BLOCKHASH`
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
Behandel validation as ’n deterministiese, begrensde preflight-funksie. As jy werklik shared state of external lookups nodig het, stoot daardie kompleksiteit na staked/reputation-tracked entities en toets die presiese bundler simulation path, nie net unit tests nie.

## 8) ERC-7702 initialization frontrun
ERC-7702 laat ’n EOA toe om smart-account code vir ’n enkele tx te laat loop. As initialization extern callable is, kan ’n frontrunner hulself as owner stel.

Mitigation: laat initialization net toe op **self-call** en net een keer.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Quick pre-merge checks
- Valideer signatures using `EntryPoint`'s `userOpHash` (binds gas fields).
- Beperk privileged functions to `EntryPoint` and/or `address(this)` as appropriate.
- Hou `validateUserOp` stateless, deterministic, and compatible with bundler simulation rules.
- Enforce EIP-712 domain separation for ERC-1271 and return `0x1626ba7e` on success.
- Hou `postOp` minimaal, bounded, and non-reverting; secure fees during validation.
- Test die first `initCode` path separately: deterministic deployment, idempotent factory behavior, and one-shot initialization.
- Run full bundler simulation (`simulateValidation` plus a traced `handleOps`) before shipping.
- For ERC-7702, allow init only on self-call and only once.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
