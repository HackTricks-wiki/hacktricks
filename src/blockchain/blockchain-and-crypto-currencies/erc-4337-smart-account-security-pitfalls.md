# Pitfalls za Usalama wa ERC-4337 Smart Account

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kupangwa. Mtiririko mkuu ni **validate-then-execute** katika bundle nzima: `EntryPoint` huthibitisha kila `UserOperation` kabla ya kutekeleza yoyote kati yake.<sup>[[5]](#references)</sup> Mpangilio huu huunda attack surface isiyo dhahiri wakati validation ni yenye ruhusa nyingi, yenye kuhifadhi state, au haiendani na sheria za bundler simulation.

## 1) Direct-call bypass ya privileged functions
Kila function ya `execute` (au inayohamisha fedha) inayoweza kuitwa externally na ambayo haijazuiwa kwa `EntryPoint` (au vetted executor module) inaweza kuitwa moja kwa moja ili ku-drain account.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Muundo salama: zuia kwa `EntryPoint`, na tumia `msg.sender == address(this)` kwa mtiririko wa usimamizi wa admin/kujisimamia (usakinishaji wa module, mabadiliko ya validator, upgrades).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Sehemu za gas zisizosainiwa au zisizokaguliwa -> kumaliza fee
Ikiwa uthibitishaji wa signature unahakiki intent (`callData`) pekee, bundler au frontrunner anaweza kuongeza fees na kumaliza ETH. Payload iliyosainiwa lazima ihusishe angalau:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: tumia `userOpHash` iliyotolewa na `EntryPoint` (ambayo inajumuisha sehemu za gas) na/au weka kikomo madhubuti kwa kila sehemu.<sup>[[2]](#references)[[5]](#references)</sup>
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
Kwa sababu validations zote huendeshwa kabla ya execution yoyote, kuhifadhi matokeo ya validation katika contract state si salama. Op nyingine katika bundle inaweza kuyaandika upya, na kusababisha execution yako itumie state iliyoathiriwa na attacker.<sup>[[2]](#references)</sup>

Epuka kuandika storage katika `validateUserOp`. Ikiwa haiwezi kuepukika, fungamanisha data ya muda kwa `userOpHash` na uifute kwa njia ya deterministic baada ya matumizi (pendelea stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` lazima ifungamanishe signatures na **contract hii** pamoja na **chain hii**. Kurecover juu ya raw hash huruhusu signatures replay kwenye accounts au chains nyingine.<sup>[[1]](#references)[[4]](#references)</sup>

Tumia EIP-712 typed data (domain iwe na `verifyingContract` na `chainId`) na urudishe exact ERC-1271 magic value `0x1626ba7e` ikiwa imefaulu.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts do not refund after validation
Baada ya `validateUserOp` kufaulu, fees huwa committed hata execution ikirevert baadaye. Attackers wanaweza kuwasilisha ops zinazoshindikana mara kwa mara na bado kukusanya fees kutoka kwenye account.<sup>[[2]](#references)</sup>

Kwa paymasters, kulipa kutoka shared pool katika `validateUserOp` na kuwatoza users katika `postOp` ni fragile kwa sababu `postOp` inaweza kurevert bila kubatilisha malipo. Linda funds wakati wa validation (per-user escrow/deposit), weka `postOp` ikiwa minimal na isiyorevert, na panga bajeti ya `paymasterPostOpGasLimit` kwa reimbursement path yenye gharama kubwa zaidi.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
`UserOperation` ya kwanza mara nyingi hubeba `initCode`, ambayo husababisha account ku-deploy kupitia **factory** wakati wa validation. Njia hii ni rahisi kutofanyiwa audit ya kutosha kwa sababu huendeshwa tu wakati wa matumizi ya kwanza.<sup>[[5]](#references)</sup>

Mifano ya failures za kawaida ni pamoja na:<sup>[[5]](#references)</sup>

- Factory/initializer inaamini `msg.sender == entryPoint`, lakini ERC-4337 deployment path **haiiti** `initCode` moja kwa moja kutoka `EntryPoint`.
- Salt, owner, validator, au module configuration haijafungamanishwa kikamilifu na signed intent, hivyo frontrunner anaweza kushindania deployment ya kwanza na kuchoma counterfactual address kwa settings zinazodhibitiwa na attacker.
- Factory si idempotent, hivyo first-use flow inayorudiwa hu-brick wallet badala ya kurudisha address iliyokwisha creatiwa.

Pattern salama: recompute sender anayetarajiwa kutoka kwenye signed deployment parameters, fanya deployment iwe deterministic (kwa kawaida `CREATE2`), na ufanye initialization mara moja tu.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Mantiki ya uthibitishaji ambayo bundlers hukataa
Code ya uthibitishaji inaweza kuwa sahihi katika majaribio ya ndani na bado isiweze kutumika katika bundlers halisi. Bundlers huendesha uthibitishaji mara nyingi na zinapaswa kufanya uthibitishaji kamili wa bundle uliotrace kabla ya kuwasilisha.<sup>[[6]](#references)</sup>

Chini ya kanuni hizo za scope ya uthibitishaji, patterns hizi ni hatari:<sup>[[6]](#references)</sup>

- Opcodes zinazotegemea block kama vile `TIMESTAMP`, `NUMBER`, au `BLOCKHASH`
- Ufikiaji wa storage nje ya scope inayoruhusiwa ya account/entity, au iteration isiyo na kikomo juu ya storage
- Calls za nje au usomaji wa oracle unaotegemea state inayoweza kubadilika nje ya scope inayoruhusiwa ya uthibitishaji

Mfano mbaya:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Chukulia validation kama preflight function ya deterministic na yenye mipaka. Ikiwa shared state au external lookups ni muhimu, fuata sheria za staked-entity na test njia hiyo hiyo ya multi-pass bundler simulation, si unit tests pekee.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 huipa EOA delegation ya kudumu kwa smart-account code; delegation hiyo haiendeshi initialization atomically. Ikiwa initialization inaweza kuitwa externally, observer anaweza kuifront-run na kujiteua kuwa owner.<sup>[[7]](#references)</sup>

Mitigation: dai calldata ya initialization iidhinishwe na EOA na uruhusu initialization mara moja pekee. Katika ERC-4337 EIP-7702 flow, pia zuia caller awe `EntryPoint.senderCreator()` pekee.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya merge
- Thibitisha signatures kwa kutumia `userOpHash` ya `EntryPoint` (inafunga sehemu za gas).
- Zuia functions zenye privileges kwa `EntryPoint` na/au `address(this)` inapofaa.
- Weka `validateUserOp` bila state, yenye matokeo yanayotabirika, na inayoendana na sheria za bundler simulation.
- Tekeleza domain separation ya EIP-712 kwa ERC-1271 na urejeshe `0x1626ba7e` inapofaulu.
- Weka `postOp` kuwa ndogo, yenye mipaka, na isiyorevert; linda fees wakati wa validation.
- Test njia ya kwanza ya `initCode` kando: deterministic deployment, tabia ya factory ya idempotent, na one-shot initialization.
- Endesha multi-pass validation ya bundler na ukaguzi wa full-bundle wenye trace kabla ya ku-deploy.
- Kwa ERC-7702, funga init kwenye authorization ya EOA na iruhusu mara moja tu; katika flows za ERC-4337, zuia caller kwa `EntryPoint.senderCreator()`.

## References

- [1] [Replay ya ERC1271 - Timu zaidi ya 15 zimeathirika (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Makosa sita katika smart accounts za ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standard Signature Validation Method for Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Set Code for EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
