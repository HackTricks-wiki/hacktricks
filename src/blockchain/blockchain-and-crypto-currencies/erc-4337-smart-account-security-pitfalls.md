# Pitfall za Usalama za ERC-4337 Smart Account

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kupangwa. Mtiririko mkuu ni **validate-then-execute** katika bundle nzima: `EntryPoint` huthibitisha kila `UserOperation` kabla ya kutekeleza yoyote kati yake. Mpangilio huu huunda attack surface isiyo dhahiri wakati validation ni permissive, ina state, au haiendani na kanuni za bundler simulation.

## 1) Direct-call bypass ya functions zenye privilege
Kila function ya `execute` (au inayohamisha fedha) inayoweza kuitwa externally na ambayo haijazuiwa kwa `EntryPoint` (au vetted executor module) inaweza kuitwa moja kwa moja ili kutoa fedha zote kwenye akaunti.<sup>[[1]](#references)</sup>
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
## 2) Unsigned or unchecked gas fields -> fee drain
Ikiwa signature validation inahakiki intent (`callData`) pekee lakini si gas-related fields, bundler au frontrunner anaweza kuongeza fees na ku-drain ETH. Signed payload lazima ihusishe angalau:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: tumia `userOpHash` iliyotolewa na `EntryPoint` (inayojumuisha gas fields) na/au weka kikomo madhubuti kwa kila field.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Kufutwa kwa validation ya Stateful (bundle semantics)
Kwa sababu validations zote huendeshwa kabla ya execution yoyote, kuhifadhi matokeo ya validation katika contract state si salama. Op nyingine katika bundle inaweza kuyafuta, na kusababisha execution yako kutumia state iliyoathiriwa na attacker.<sup>[[1]](#references)</sup>

Epuka kuandika storage katika `validateUserOp`. Ikiwa haiwezi kuepukika, funga data ya muda kwa `userOpHash` na uifute kwa njia ya deterministically baada ya matumizi (pendelea validation isiyotumia state).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay katika accounts/chains (domain separation haipo)
`isValidSignature(bytes32 hash, bytes sig)` lazima ifunge signatures kwa **contract hii** na **chain hii**. Kurecover juu ya raw hash kunaruhusu signatures kureplayiwa katika accounts au chains nyingine.<sup>[[1]](#references)</sup>

Tumia EIP-712 typed data (domain inajumuisha `verifyingContract` na `chainId`) na urudishe magic value halisi ya ERC-1271 `0x1626ba7e` ikiwa imefaulu.<sup>[[1]](#references)</sup>

## 5) Reverts hazirefund baada ya validation
Mara `validateUserOp` inapofaulu, fees huwa zimecommitwa hata kama execution baadaye inarevert. Attackers wanaweza kuwasilisha ops zitakazofeli mara kwa mara na bado kukusanya fees kutoka kwenye account.<sup>[[1]](#references)</sup>

Kwa paymasters, kulipa kutoka shared pool katika `validateUserOp` na kuwatoza users katika `postOp` ni hatari kwa sababu `postOp` inaweza kurevert bila kubatilisha malipo. Linda funds wakati wa validation (per-user escrow/deposit), weka `postOp` iwe ndogo na isiyorevert, na panga bajeti ya `paymasterPostOpGasLimit` kwa reimbursement path yenye gharama kubwa zaidi.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory assumptions
`UserOperation` ya kwanza mara nyingi hubeba `initCode`, ambayo husababisha account ideployiwe kupitia **factory** wakati wa validation. Path hii ni rahisi kukaguliwa kwa kiwango kidogo kwa sababu huendeshwa tu wakati wa matumizi ya kwanza.<sup>[[2]](#references)</sup>

Mifumo ya kushindwa ya kawaida:

- Factory/initializer inaamini `msg.sender == entryPoint`, lakini deployment path ya ERC-4337 **haiiti** `initCode` moja kwa moja kutoka `EntryPoint`.
- Salt, owner, validator, au usanidi wa module haujafungwa kikamilifu kwenye intent iliyosainiwa, kwa hiyo frontrunner anaweza kushindania deployment ya kwanza na kuichoma counterfactual address kwa settings zinazodhibitiwa na attacker.
- Factory si idempotent, kwa hiyo flow ya matumizi ya kwanza inayorudiwa hu-brick wallet badala ya kurudisha address iliyokwisha kuundwa.

Pattern salama: hesabu upya sender anayetarajiwa kutoka kwa deployment parameters zilizosainiwa, fanya deployment iwe deterministic (kwa kawaida `CREATE2`), na ufanye initialization itekelezwe mara moja tu.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Mantiki ya validation ambayo bundlers hukataa
Validation code inaweza kuwa sahihi katika majaribio ya ndani na bado isiweze kutumika katika bundlers halisi. Public bundlers huiga `validateUserOp()` / `validatePaymasterUserOp()` off-chain na kwa kawaida huendesha `debug_traceCall(handleOps)` kamili kabla ya inclusion.

Hii hufanya mifumo ifuatayo kuwa hatari ndani ya validation:

- Block-dependent opcodes kama vile `TIMESTAMP`, `NUMBER`, au `BLOCKHASH`
- State writes kama vile `SSTORE`
- Ujirudiaji usio na kikomo kwenye storage
- External calls au oracle reads za kiholela zinazoweza kubadilika kati ya simulation na inclusion

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
Chukulia validation kama function ya preflight iliyo deterministic na yenye mipaka. Ikiwa unahitaji kweli shared state au external lookups, hamishia utata huo kwenye entities zinazowekwa stake na kufuatiliwa reputation, kisha test exact bundler simulation path, si unit tests pekee.

## 8) ERC-7702 initialization frontrun
ERC-7702 huwezesha EOA kuendesha smart-account code kwa tx moja. Ikiwa initialization inaweza kuitwa externally, frontrunner anaweza kujiweka kama owner.<sup>[[1]](#references)</sup>

Kinga: ruhusu initialization kupitia **self-call** pekee na mara moja tu.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya kuunganisha
- Thibitisha signatures kwa kutumia `EntryPoint`'s `userOpHash` (inayofunga gas fields).
- Zuia privileged functions kwa `EntryPoint` na/au `address(this)` inapofaa.
- Weka `validateUserOp` bila state, yenye matokeo yanayoweza kubashiriwa, na inayooana na sheria za bundler simulation.
- Tekeleza EIP-712 domain separation kwa ERC-1271 na urudishe `0x1626ba7e` ikiwa imefaulu.
- Weka `postOp` kuwa ndogo, yenye mipaka, na isiyofeli; linda fees wakati wa validation.
- Pima njia ya kwanza ya `initCode` kando: deterministic deployment, tabia ya factory ya idempotent, na initialization ya mara moja tu.
- Endesha bundler simulation kamili (`simulateValidation` pamoja na `handleOps` iliyofuatiliwa) kabla ya kusafirisha.
- Kwa ERC-7702, ruhusu init tu kupitia self-call na mara moja pekee.



## Marejeo

- [1] [Makosa sita katika ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction kwa kutumia Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
