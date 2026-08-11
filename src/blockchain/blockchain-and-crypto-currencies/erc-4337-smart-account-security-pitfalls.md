# Mapungufu ya Usalama ya ERC-4337 Smart Account

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kupangwa. Mtiririko mkuu ni **validate-then-execute** katika bundle nzima: `EntryPoint` huthibitisha kila `UserOperation` kabla ya kutekeleza yoyote kati yake.<sup>[[5]](#references)</sup> Mpangilio huu huunda attack surface isiyo dhahiri wakati validation inaruhusu kupita, ina state, au haiendani na sheria za bundler simulation.

## 1) Direct-call bypass ya functions zenye privilege
Function yoyote ya `execute` inayoweza kuitwa externally (au function inayohamisha fedha) ambayo haijazuiwa kwa `EntryPoint` (au vetted executor module) inaweza kuitwa moja kwa moja ili kuiba fedha za account.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Muundo salama: zuia kwa `EntryPoint`, na tumia `msg.sender == address(this)` kwa mtiririko wa admin/self-management (usakinishaji wa module, mabadiliko ya validator, upgrades).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Sehemu za gas zisizosainiwa au kuthibitishwa -> kuvuja kwa ada
Ikiwa signature validation inashughulikia intent (`callData`) pekee lakini si sehemu zinazohusiana na gas, bundler au frontrunner anaweza kuongeza ada na kuvuja ETH. Payload iliyosainiwa lazima ihusishe angalau:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Muundo wa kujilinda: tumia `userOpHash` iliyotolewa na `EntryPoint` (inayojumuisha sehemu za gas) na/au weka kikomo madhubuti kwa kila sehemu.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Kuharibiwa kwa state wakati wa validation (bundle semantics)
Kwa sababu validations zote huendeshwa kabla ya execution yoyote, kuhifadhi matokeo ya validation kwenye contract state si salama. Op nyingine katika bundle hiyo hiyo inaweza kuyaandika upya, na kusababisha execution yako itumie state iliyoathiriwa na attacker.<sup>[[2]](#references)</sup>

Epuka kuandika storage ndani ya `validateUserOp`. Ikiwa haiwezi kuepukika, funga temporary data kwa kutumia `userOpHash` na uifute kwa utaratibu maalum baada ya matumizi (pendelea stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay kati ya accounts/chains (domain separation inayokosekana)
`isValidSignature(bytes32 hash, bytes sig)` lazima ifunge signatures kwa **contract hii** na **chain hii**. Kurecover juu ya raw hash kunaruhusu signatures kutumika tena kwenye accounts au chains nyingine.<sup>[[1]](#references)[[4]](#references)</sup>

Tumia EIP-712 typed data (domain inajumuisha `verifyingContract` na `chainId`) na urudishe exact ERC-1271 magic value `0x1626ba7e` endapo imefaulu.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts hazirudishi malipo baada ya validation
Mara `validateUserOp` inapofaulu, fees huwa zimecommitiwa hata kama execution baadaye itarevert. Attackers wanaweza kuwasilisha ops zitakazofeli mara kwa mara na bado kukusanya fees kutoka kwenye account.<sup>[[2]](#references)</sup>

Kwa paymasters, kulipa kutoka shared pool ndani ya `validateUserOp` na kuwatoza users ndani ya `postOp` ni hatari kwa sababu `postOp` inaweza kurevert bila kuondoa malipo yaliyofanyika. Linda funds wakati wa validation (per-user escrow/deposit), weka `postOp` iwe ndogo na isiyorevert, na tenga bajeti ya `paymasterPostOpGasLimit` kwa reimbursement path yenye gharama kubwa zaidi.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
`UserOperation` ya kwanza mara nyingi hubeba `initCode`, ambayo husababisha account ideployiwe kupitia **factory** wakati wa validation. Njia hii ni rahisi kutokaguliwa vya kutosha kwa sababu huendeshwa tu wakati wa matumizi ya kwanza.<sup>[[5]](#references)</sup>

Mifano ya failures za kawaida ni pamoja na:<sup>[[5]](#references)</sup>

- Factory/initializer inaamini kuwa `msg.sender == entryPoint`, lakini njia ya deployment ya ERC-4337 **haiiti** `initCode` moja kwa moja kutoka kwa `EntryPoint`.
- Salt, owner, validator, au module configuration haijafungwa kikamilifu kwenye signed intent, hivyo frontrunner anaweza kushindania deployment ya kwanza na kuichukua counterfactual address kwa settings zinazodhibitiwa na attacker.
- Factory si idempotent, hivyo first-use flow inayorudiwa huifanya wallet ishindwe kufanya kazi badala ya kurudisha address ambayo tayari imeundwa.

Safe pattern: hesabu upya sender anayetarajiwa kutoka kwenye signed deployment parameters, fanya deployment iwe deterministic (kwa kawaida `CREATE2`), na ufanye initialization itekelezwe mara moja tu.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Mantiki ya validation ambayo bundlers hukataa
Code ya validation inaweza kuwa sahihi katika majaribio ya local na bado isiweze kutumika katika bundlers halisi. Bundlers huendesha validation mara nyingi na inapaswa kufanya validation kamili ya bundle iliyofuatiliwa kabla ya submission.<sup>[[6]](#references)</sup>

Chini ya kanuni hizo za scope ya validation, mifumo hii ni hatari:<sup>[[6]](#references)</sup>

- Opcodes zinazotegemea block kama vile `TIMESTAMP`, `NUMBER`, au `BLOCKHASH`
- Ufikiaji wa storage nje ya scope inayoruhusiwa ya account/entity, au iteration isiyo na kikomo kwenye storage
- Calls za nje au usomaji wa oracle unaotegemea state inayoweza kubadilika nje ya scope inayoruhusiwa ya validation

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
Chukulia validation kama preflight function ya deterministic yenye kikomo. Ikiwa shared state au external lookups ni muhimu, fuata staked-entity rules na test multi-pass bundler simulation path hiyo hiyo, si unit tests pekee.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 huipa EOA delegation endelevu kwa smart-account code; delegation hiyo haiendeshi initialization atomiki. Ikiwa initialization inaweza kuitwa externally, observer anaweza kuifront-run na kujiweka kama owner.<sup>[[7]](#references)</sup>

Mitigation: hitaji initialization calldata iidhinishwe na EOA na uruhusu initialization mara moja pekee. Katika ERC-4337 EIP-7702 flow, pia zuia caller kwa `EntryPoint.senderCreator()` pekee.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya kuunganisha
- Thibitisha signatures ukitumia `EntryPoint`'s `userOpHash` (inayofunga gas fields).
- Zuia privileged functions kwa `EntryPoint` na/au `address(this)` inapofaa.
- Weka `validateUserOp` ikiwa stateless, deterministic, na inayooana na sheria za bundler simulation.
- Tekeleza EIP-712 domain separation kwa ERC-1271 na urudishe `0x1626ba7e` inapofaulu.
- Weka `postOp` ikiwa minimal, yenye mipaka, na isiyofanya revert; linda fees wakati wa validation.
- Test njia ya kwanza ya `initCode` kando: deterministic deployment, tabia ya factory ya idempotent, na one-shot initialization.
- Endesha multi-pass validation ya bundler na ukaguzi wa full-bundle wenye tracing kabla ya ku-deploy.
- Kwa ERC-7702, funga init kwenye uidhinishaji wa EOA na iruhusu mara moja pekee; katika mtiririko wa ERC-4337, zuia caller kwa `EntryPoint.senderCreator()`.

## References

- [1] [ERC1271 Replay - Timu 15+ Zimeathirika (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Makosa sita katika smart accounts za ERC-4337 (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Mbinu ya Kawaida ya Uthibitishaji wa Signature kwa Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing na signing ya data iliyopangwa kwa aina](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction kwa Kutumia Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Sheria za Wigo wa Validation za Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Kuweka Code kwa EOAs](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
