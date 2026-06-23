# ERC-4337 Smart Account Security Pitfalls

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 account abstraction verwandelt Wallets in programmierbare Systeme. Der zentrale Ablauf ist **validate-then-execute** über ein ganzes Bundle hinweg: Das `EntryPoint` validiert jede `UserOperation`, bevor irgendeine davon ausgeführt wird. Diese Reihenfolge erzeugt eine nicht offensichtliche Angriffsfläche, wenn die Validierung permissiv, zustandsabhängig oder inkonsistent mit den Simulationsregeln des bundlers ist.

## 1) Direct-call bypass of privileged functions
Jede extern aufrufbare `execute`- (oder fonds-bewegende) Funktion, die nicht auf `EntryPoint` (oder ein geprüftes Executor-Modul) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Self-Management-Flows verwenden (Modul-Installation, Validator-Änderungen, Upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Unsignierte oder ungeprüfte gas-Felder -> fee drain
Wenn die Signaturprüfung nur die Absicht (`callData`), aber nicht gas-bezogene Felder abdeckt, kann ein bundler oder frontrunner die Gebühren aufblasen und ETH drain. Das signierte Payload muss mindestens binden:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensives Muster: Verwende das von `EntryPoint` bereitgestellte `userOpHash` (das gas-Felder einschließt) und/oder begrenze jedes Feld strikt.
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
Because all validations run before any execution, storing validation results in contract state is unsafe. Another op in the same bundle can overwrite it, causing your execution to use attacker-influenced state.

Vermeide es, Storage in `validateUserOp` zu schreiben. Falls unvermeidbar, tagge temporäre Daten mit `userOpHash` und lösche sie deterministisch nach der Nutzung (bevorzuge stateless validation).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Das Recovern über einen rohen Hash erlaubt, dass Signaturen über Accounts oder Chains hinweg replayt werden.

Verwende EIP-712 typed data (Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg exakt den ERC-1271 Magic Value `0x1626ba7e` zurück.

## 5) Reverts do not refund after validation
Sobald `validateUserOp` erfolgreich ist, sind Fees committed, selbst wenn die Execution später revertet. Angreifer können wiederholt Ops einreichen, die fehlschlagen, und trotzdem Fees vom Account einziehen.

Für Paymaster ist es fragil, während `validateUserOp` aus einem gemeinsamen Pool zu zahlen und User in `postOp` zu belasten, weil `postOp` reverten kann, ohne die Zahlung rückgängig zu machen. Sichere Funds während der Validation ab (per-user escrow/deposit), halte `postOp` minimal und non-reverting, und budgetiere `paymasterPostOpGasLimit` für den Worst-Case-Reimbursement-Pfad.

## 6) Counterfactual deployment / factory assumptions
Die erste `UserOperation` trägt oft `initCode`, wodurch der Account während der Validation über eine **factory** deployed wird. Dieser Pfad ist leicht unterzureviewen, weil er nur bei der ersten Nutzung läuft.

Häufige Fehler:

- Die factory/der Initializer vertraut auf `msg.sender == entryPoint`, aber der ERC-4337-Deployment-Pfad ruft `initCode` nicht direkt von `EntryPoint` aus auf.
- Der Salt, Owner, Validator oder die Module-Konfiguration ist nicht vollständig an die signierte Intent gebunden, sodass ein Frontrunner das erste Deployment rennen und die counterfactual address mit attacker-controlled Settings verbrennen kann.
- Die factory ist nicht idempotent, sodass ein wiederholter First-Use-Flow das Wallet bricked, statt die bereits erzeugte Address zurückzugeben.

Sicheres Pattern: Berechne den erwarteten Sender aus den signierten Deployment-Parametern neu, mache das Deployment deterministisch (typischerweise `CREATE2`) und mache die Initialisierung one-shot.
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation-Logik, die bundlers ablehnen
Validation-Code kann in lokalen Tests korrekt sein und trotzdem in echten bundlers unbrauchbar sein. Öffentliche bundlers simulieren `validateUserOp()` / `validatePaymasterUserOp()` off-chain und führen vor der Aufnahme oft ein vollständiges `debug_traceCall(handleOps)` aus.

Das macht diese Muster innerhalb der Validation gefährlich:

- Block-abhängige Opcodes wie `TIMESTAMP`, `NUMBER` oder `BLOCKHASH`
- State-Writes wie `SSTORE`
- Unbegrenzte Iteration über Storage
- Beliebige externe Calls oder oracle reads, die sich zwischen Simulation und Aufnahme ändern können

Schlechtes Beispiel:
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
Behandle Validierung als deterministische, begrenzte Preflight-Funktion. Wenn du wirklich gemeinsamen Zustand oder externe Lookups brauchst, verlagere diese Komplexität in staked/reputation-getrackte Entities und teste den exakten bundler-Simulationspfad, nicht nur Unit-Tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 erlaubt es einer EOA, Smart-Account-Code für eine einzelne tx auszuführen. Wenn die initialization extern aufrufbar ist, kann ein frontrunner sich selbst als owner setzen.

Mitigation: erlaube initialization nur per **self-call** und nur einmal.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Quick pre-merge checks
- Signaturen mit `EntryPoint`'s `userOpHash` validieren (bindet Gas-Felder).
- Privilegierte Funktionen auf `EntryPoint` und/oder `address(this)` beschränken, je nach Fall.
- `validateUserOp` stateless, deterministic und kompatibel mit den bundler Simulation Rules halten.
- EIP-712 domain separation für ERC-1271 erzwingen und bei Erfolg `0x1626ba7e` zurückgeben.
- `postOp` minimal, bounded und non-reverting halten; Gebühren während der Validierung absichern.
- Den ersten `initCode`-Pfad separat testen: deterministic deployment, idempotent factory behavior und one-shot initialization.
- Vor dem Shipping die vollständige bundler simulation (`simulateValidation` plus ein getracktes `handleOps`) ausführen.
- Für ERC-7702 init nur bei self-call und nur einmal erlauben.



## References

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [https://eips.ethereum.org/EIPS/eip-4337](https://eips.ethereum.org/EIPS/eip-4337)
{{#include ../../banners/hacktricks-training.md}}
