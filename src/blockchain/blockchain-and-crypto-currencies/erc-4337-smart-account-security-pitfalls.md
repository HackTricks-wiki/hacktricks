# ERC-4337 Hatari za Usalama za Akaunti Mahiri

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction hubadilisha wallets kuwa mifumo inayoweza kuprogramiwa. Mtiririko wa msingi ni **validate-then-execute** kwa kifurushi kizima: `EntryPoint` inathibitisha kila `UserOperation` kabla ya kutekeleza yoyote yao. Mpangilio huu unaunda uso wa shambulio usio dhahiri wakati uthibitisho ni wa kuruhusu au unaotegemea hali (stateful).

## 1) Direct-call bypass ya kazi zilizo na mamlaka
Kazi yoyote inayoweza kuitwa kutoka nje `execute` (au inayohamisha fedha) ambayo haizuiliwi kwa `EntryPoint` (au module ya executor iliyokaguliwa) inaweza kuitwa moja kwa moja kutonya fedha kutoka kwenye akaunti.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Mfano salama: ruhusu tu `EntryPoint`, na tumia `msg.sender == address(this)` kwa mtiririko za admin/kujisimamia (kufunga module, mabadiliko ya validator, masasisho).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Sehemu za gas zisizosainiwa au zisizokaguliwa -> upotevu wa ada
Ikiwa uthibitisho wa saini unafunika tu nia (`callData`) lakini sio mashamba yanayohusiana na gas, bundler au frontrunner anaweza kupandisha ada na kuondoa ETH. Payload iliyosainiwa inapaswa kufunga angalau:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Mfano la kujikinga: tumia `EntryPoint`-provided `userOpHash` (ambayo inajumuisha mashamba za gas) na/au weka kikomo kali kwa kila shamba.
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
Kwa sababu validations zote zinaenda kabla ya utekelezaji wowote, kuhifadhi matokeo ya uhakiki katika state ya contract ni hatari. Operesheni nyingine katika bundle ile ile inaweza kuiandika tena, ikasababisha utekelezaji wako kutumia state iliyodhibitiwa na mshambulizi.

Epuka kuandika storage ndani ya `validateUserOp`. Ikiwa haiwezi kuepukika, tumia `userOpHash` kama ufunguo wa data ya muda na uifute kwa njia deterministic baada ya matumizi (pendelea stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` lazima iambatane na sahihi kwa **mkataba huu** na **mnyororo huu**. Kupata sahihi juu ya hash ghafi kunaruhusu sahihi kurudishwa tena katika akaunti au mnyororo tofauti.

Tumia EIP-712 typed data (domain inajumuisha `verifyingContract` na `chainId`) na rudisha thamani maalum ya ERC-1271 `0x1626ba7e` ukiwafaulu.

## 5) Reverts do not refund after validation
Mara `validateUserOp` ikifanikiwa, ada zimewekwa (committed) hata ikiwa utekelezaji utarevert baadaye. Washambulizi wanaweza kuwasilisha ops mara kwa mara zitakazoshindwa na bado wakusanye ada kutoka kwenye akaunti.

Kwa paymasters, kulipa kutoka pool iliyoshirikiwa ndani ya `validateUserOp` na kutoza watumiaji katika `postOp` ni hatarishi kwa sababu `postOp` inaweza ku-revert bila kurudisha malipo. Linda fedha wakati wa uhakiki (escrow/deposit kwa kila mtumiaji), na fanya `postOp` iwe ndogo na isiyorevert.

## 6) ERC-7702 initialization frontrun
ERC-7702 inaruhusu EOA kuendesha code ya smart-account kwa tx moja. Ikiwa initialization inaweza kuitwa kutoka nje, frontrunner anaweza kujipangia kuwa owner.

Kupunguza hatari: ruhusu initialization tu kwa **self-call** na mara moja tu.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Ukaguzi wa haraka kabla ya kuunganisha
- Thibitisha saini ukitumia `userOpHash` ya `EntryPoint` (inashikilia viwanja vya gesi).
- Zuia functions zilizo na mamlaka kwa `EntryPoint` na/au `address(this)`, inapofaa.
- Weka `validateUserOp` isiyo na state.
- Lazimisha utenganisho wa domain wa EIP-712 kwa ERC-1271 na urejeshe `0x1626ba7e` wakati wa mafanikio.
- Fanya `postOp` ndogo, yenye mipaka, na isiyorudisha; hakikisha ada zimehifadhiwa wakati wa uthibitisho.
- Kwa ERC-7702, ruhusu init tu kwenye self-call na mara moja tu.

## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
