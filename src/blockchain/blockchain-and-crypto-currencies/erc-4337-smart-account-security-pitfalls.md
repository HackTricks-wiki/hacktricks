# Hatari za Usalama za Smart Account za ERC-4337

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kupangwa. Mtiririko mkuu ni **validate-then-execute** katika bundle nzima: `EntryPoint` huthibitisha kila `UserOperation` kabla ya kutekeleza yoyote kati yao. Mpangilio huu huunda attack surface isiyo dhahiri wakati uthibitishaji ni wa kuruhusu kupita kiasi, unaotegemea state, au haupatani na kanuni za bundler simulation.

## 1) Direct-call bypass ya functions zenye privileges
Function yoyote ya `execute` inayoweza kuitwa externally (au function inayohamisha funds) ambayo haijazuiwa kwa `EntryPoint` (au vetted executor module) inaweza kuitwa moja kwa moja ili ku-drain akaunti.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Muundo salama: zuia kwa `EntryPoint`, na tumia `msg.sender == address(this)` kwa mtiririko wa admin/usimamizi wa ndani (usakinishaji wa module, mabadiliko ya validator, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Sehemu za gas zisizosainiwa au zisizokaguliwa -> kuvuja kwa ada
Ikiwa signature validation inahakiki intent (`callData`) pekee lakini si sehemu zinazohusiana na gas, bundler au frontrunner anaweza kuongeza ada na kuvuja ETH. Payload iliyosainiwa lazima ijumuishe angalau:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Muundo wa kujilinda: tumia `userOpHash` iliyotolewa na `EntryPoint` (inayojumuisha sehemu za gas) na/au weka kikomo madhubuti kwa kila sehemu.<sup>[[1]](#references)</sup>
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
Kwa sababu validations zote huendeshwa kabla ya execution yoyote, kuhifadhi matokeo ya validation katika contract state si salama. Op nyingine katika bundle inaweza kuyaandika upya, na kusababisha execution yako kutumia state iliyoathiriwa na attacker.<sup>[[1]](#references)</sup>

Epuka kuandika storage katika `validateUserOp`. Ikiwa haiwezi kuepukika, funga temporary data kwa `userOpHash` na uifute kwa utaratibu uliowekwa baada ya kutumiwa (pendelea stateless validation).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` lazima ihusishe signatures na **contract hii** pamoja na **chain hii**. Kus recover juu ya raw hash kunaruhusu signatures kureplay across accounts au chains.<sup>[[1]](#references)</sup>

Tumia EIP-712 typed data (domain inajumuisha `verifyingContract` na `chainId`) na urudishe exact ERC-1271 magic value `0x1626ba7e` ikiwa imefaulu.<sup>[[1]](#references)</sup>

## 5) Reverts do not refund after validation
Baada ya `validateUserOp` kufaulu, fees huwa zimecommitwa hata kama execution itarevert baadaye. Attackers wanaweza kuwasilisha ops zitakazofeli mara kwa mara na bado kukusanya fees kutoka kwenye account.<sup>[[1]](#references)</sup>

Kwa paymasters, kulipa kutoka shared pool katika `validateUserOp` na kuwacharge users katika `postOp` ni fragile kwa sababu `postOp` inaweza kurevert bila kurejesha malipo. Linda funds wakati wa validation (per-user escrow/deposit), weka `postOp` ikiwa minimal na isiyorevert, na utenge `paymasterPostOpGasLimit` kwa reimbursement path yenye worst-case.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
`UserOperation` ya kwanza mara nyingi hubeba `initCode`, ambayo husababisha account ideploy kupitia **factory** wakati wa validation. Njia hii ni rahisi kukaguliwa kwa kiwango kidogo kwa sababu huendeshwa tu wakati wa first use.<sup>[[2]](#references)</sup>

Common failures:

- Factory/initializer inaamini `msg.sender == entryPoint`, lakini ERC-4337 deployment path **haiiti** `initCode` moja kwa moja kutoka `EntryPoint`.
- Salt, owner, validator, au module configuration haijafungwa kikamilifu kwenye signed intent, hivyo frontrunner anaweza kushindana kwenye first deployment na kuichoma counterfactual address kwa settings zinazodhibitiwa na attacker.
- Factory si non-idempotent, hivyo first-use flow inayorudiwa inabrick wallet badala ya kurudisha address ambayo tayari imeundwa.

Safe pattern: recompute sender anayetarajiwa kutoka kwenye signed deployment parameters, fanya deployment iwe deterministic (kwa kawaida `CREATE2`), na ufanye initialization iwe one-shot.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logic that bundlers reject
Validation code inaweza kuwa sahihi katika local tests na bado isiweze kutumika katika bundlers halisi. Public bundlers huiga `validateUserOp()` / `validatePaymasterUserOp()` off-chain na kwa kawaida huendesha `debug_traceCall(handleOps)` kamili kabla ya inclusion.<sup>[[3]](#references)</sup>

Hilo hufanya mifumo hii kuwa hatari ndani ya validation:

- Block-dependent opcodes kama vile `TIMESTAMP`, `NUMBER`, au `BLOCKHASH`
- State writes kama vile `SSTORE`
- Iteration isiyo na kikomo kwenye storage
- External calls za kiholela au oracle reads zinazoweza kubadilika kati ya simulation na inclusion

Bad example:
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
Chukulia validation kama preflight function yenye matokeo bainifu na mipaka. Ikiwa kwa kweli unahitaji shared state au external lookups, hamishia ugumu huo kwenye entities zenye staking/reputation tracking na test njia kamili ya bundler simulation, si unit tests pekee.

## 8) ERC-7702 frontrun ya uanzishaji
ERC-7702 inaruhusu EOA kuendesha smart-account code kwa tx moja. Ikiwa uanzishaji unaweza kuitwa kutoka nje, frontrunner anaweza kujiteua kuwa owner.<sup>[[1]](#references)</sup>

Hatua ya kuzuia: ruhusu uanzishaji pekee kupitia **self-call**, na uruhusu ufanyike mara moja tu.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya kuunganisha
- Thibitisha signatures kwa kutumia `userOpHash` ya `EntryPoint` (inayofunga gas fields).
- Zuia functions zenye privileged access zitumike na `EntryPoint` na/au `address(this)` ipasavyo.
- Weka `validateUserOp` ikiwa stateless, deterministic, na inayoendana na bundler simulation rules.
- Tekeleza EIP-712 domain separation kwa ERC-1271 na urudishe `0x1626ba7e` wakati wa mafanikio.
- Weka `postOp` ikiwa ndogo, yenye mipaka, na isiyofanya revert; linda fees wakati wa validation.
- Test njia ya kwanza ya `initCode` kando: deterministic deployment, tabia ya factory ya idempotent, na initialization ya mara moja tu.
- Endesha bundler simulation kamili (`simulateValidation` pamoja na `handleOps` iliyofuatiliwa) kabla ya ku-deploy.
- Kwa ERC-7702, ruhusu init kupitia self-call pekee na mara moja tu.

## Marejeo

- [1] [Makosa sita katika ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
