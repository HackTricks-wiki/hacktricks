# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kuprogramiwa. Mtiririko wa msingi ni **validate-then-execute** kwa bundle nzima: `EntryPoint` huthibitisha kila `UserOperation` kabla ya kutekeleza yoyote kati yao. Mpangilio huu huunda attack surface isiyo dhahiri wakati validation ni permissive, stateful, au haiendani na bundler simulation rules.

## 1) Direct-call bypass of privileged functions
Kila `execute` inayoweza kuitwa kwa nje (au fund-moving) function ambayo haizuiliwi kwa `EntryPoint` (au vetted executor module) inaweza kuitwa moja kwa moja ili kuondoa fedha za account.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Muundo salama: weka kizuizi kwa `EntryPoint`, na tumia `msg.sender == address(this)` kwa mtiririko wa admin/self-management (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsigned or unchecked gas fields -> fee drain
Ikiwa uthibitishaji wa saini unahusisha tu intent (`callData`) lakini si fields zinazohusiana na gas, bundler au frontrunner anaweza kuongeza fees na kumaliza ETH. Payload iliyosainiwa lazima ifunge angalau:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: tumia `userOpHash` iliyotolewa na `EntryPoint` (ambayo inajumuisha gas fields) na/au weka strict cap kwa kila field.
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
Kwa sababu uthibitishaji wote unaendeshwa kabla ya execution yoyote, kuhifadhi matokeo ya validation katika state ya contract si salama. Op nyingine ndani ya bundle ile ile inaweza kuyafutia/kuyaandika upya, na kusababisha execution yako kutumia state iliyoathiriwa na attacker.

Epuka kuandika storage katika `validateUserOp`. Ikiwa haiwezekani, key data ya muda kwa `userOpHash` na ifute kwa njia ya deterministic baada ya matumizi (prefer stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` lazima ifunge signatures kwa **contract hii** na **chain hii**. Kurecover kutoka kwenye raw hash huruhusu signatures kufanya replay across accounts au chains.

Tumia EIP-712 typed data (domain inajumuisha `verifyingContract` na `chainId`) na rudisha exact ERC-1271 magic value `0x1626ba7e` inapofanikiwa.

## 5) Reverts do not refund after validation
Mara `validateUserOp` inapofanikiwa, fees zinakuwa committed hata kama execution baadaye inarevert. Attackers wanaweza kuwasilisha mara kwa mara ops ambazo zitafeli na bado kukusanya fees kutoka kwa account.

Kwa paymasters, kulipa kutoka kwenye shared pool katika `validateUserOp` na kutoza users katika `postOp` ni fragile kwa sababu `postOp` inaweza kurevert bila kufuta malipo. Linda funds wakati wa validation (per-user escrow/deposit), weka `postOp` kuwa minimal na non-reverting, na budget `paymasterPostOpGasLimit` kwa worst-case reimbursement path.

## 6) Counterfactual deployment / factory assumptions
`UserOperation` ya kwanza mara nyingi hubeba `initCode`, ambayo husababisha account ku-deployed kupitia **factory** wakati wa validation. Path hii ni rahisi ku-under-audit kwa sababu inaendeshwa tu wakati wa matumizi ya kwanza.

Failures za kawaida:

- Factory/initializer inaamini `msg.sender == entryPoint`, lakini ERC-4337 deployment path haiitwi `initCode` moja kwa moja kutoka `EntryPoint`.
- Salt, owner, validator, au module configuration haifungwi kikamilifu kwa signed intent, hivyo frontrunner anaweza kushindania first deployment na ku-burn counterfactual address kwa settings zinazodhibitiwa na attacker.
- Factory si idempotent, hivyo repeated first-use flow hu-brick wallet badala ya kurudisha address ambayo tayari imeundwa.

Safe pattern: recompute expected sender kutoka kwa signed deployment parameters, fanya deployment iwe deterministic (kawaida `CREATE2`), na fanya initialization iwe one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Mantiki ya uthibitishaji ambayo bundlers hukataa
Msimbo wa uthibitishaji unaweza kuwa sahihi kwenye majaribio ya ndani lakini bado usitumike kwenye bundlers halisi. Public bundlers huiga `validateUserOp()` / `validatePaymasterUserOp()` off-chain na kwa kawaida huendesha `debug_traceCall(handleOps)` kamili kabla ya kuingizwa.

Hilo linafanya mifumo hii iwe hatari ndani ya validation:

- Opcodes zinazotegemea block kama `TIMESTAMP`, `NUMBER`, au `BLOCKHASH`
- Uandishi wa state kama `SSTORE`
- Iteration isiyo na kikomo juu ya storage
- Arbitrary external calls au oracle reads ambazo zinaweza kubadilika kati ya simulation na inclusion

Mfano mbaya:
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
Tumia validation kama kazi ya preflight ya deterministic, bounded. Ikiwa kweli unahitaji shared state au external lookups, sogeza complexity hiyo ndani ya staked/reputation-tracked entities na test exact bundler simulation path, si unit tests pekee.

## 8) ERC-7702 initialization frontrun
ERC-7702 inamruhusu EOA kuendesha smart-account code kwa tx moja. Ikiwa initialization inaweza kuitwa kutoka nje, frontrunner anaweza kujiteua mwenyewe kama owner.

Mitigation: ruhusu initialization tu kwenye **self-call** na mara moja tu.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya kuunganisha
- Thibitisha signatures kwa kutumia `EntryPoint`'s `userOpHash` (hufunga fields za gas).
- Zuia privileged functions kwa `EntryPoint` na/au `address(this)` inapofaa.
- Weka `validateUserOp` bila state, deterministic, na inayoendana na bundler simulation rules.
- Tekeleza EIP-712 domain separation kwa ERC-1271 na rudisha `0x1626ba7e` ikifaulu.
- Weka `postOp` iwe minimal, bounded, na isiyoreverti; linda fees wakati wa validation.
- Jaribu first `initCode` path kando: deterministic deployment, idempotent factory behavior, na one-shot initialization.
- Endesha full bundler simulation (`simulateValidation` pamoja na traced `handleOps`) kabla ya kupeleka.
- Kwa ERC-7702, ruhusu init tu kwenye self-call na mara moja tu.



## Marejeo

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
