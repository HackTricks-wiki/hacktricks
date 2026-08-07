# Sicherheitsrisiken bei ERC-4337 Smart Accounts

{{#include ../../banners/hacktricks-training.md}}

Die Kontoabstraktion von ERC-4337 verwandelt Wallets in programmierbare Systeme. Der zentrale Ablauf folgt dem Prinzip **validate-then-execute** über ein gesamtes Bundle: Der `EntryPoint` validiert jede `UserOperation`, bevor er eine davon ausführt. Diese Reihenfolge schafft eine nicht offensichtliche Angriffsfläche, wenn die Validierung zu permissiv oder zustandsbehaftet ist oder nicht mit den Simulationsregeln des Bundlers übereinstimmt.

## 1) Umgehung privilegierter Funktionen durch direkte Aufrufe
Jede extern aufrufbare `execute`- (oder geldbewegende) Funktion, die nicht auf den `EntryPoint` (oder ein geprüftes Executor-Modul) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Selbstverwaltungsabläufe (Modulinstallation, Validatoränderungen, Upgrades) verwenden.
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nicht signierte oder ungeprüfte Gasfelder -> Gebührenabfluss
Wenn die Signaturvalidierung nur die Absicht (`callData`), aber nicht die gasbezogenen Felder abdeckt, kann ein Bundler oder Frontrunner die Gebühren erhöhen und ETH abziehen. Das signierte Payload muss mindestens Folgendes binden:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensives Muster: Verwende den von `EntryPoint` bereitgestellten `userOpHash` (der die Gasfelder enthält) und/oder begrenze jedes Feld strikt.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Stateful validation clobbering (Bundle-Semantik)
Da alle Validierungen vor jeder Ausführung erfolgen, ist das Speichern von Validierungsergebnissen im Contract-State unsicher. Eine andere Op im selben Bundle kann diesen Wert überschreiben, sodass deine Ausführung von einem durch den Angreifer beeinflussten State abhängt.<sup>[[1]](#references)</sup>

Vermeide das Schreiben in den Storage innerhalb von `validateUserOp`. Falls dies unvermeidbar ist, müssen temporäre Daten anhand von `userOpHash` indiziert und nach der Verwendung deterministisch gelöscht werden (stateless validation wird bevorzugt).<sup>[[1]](#references)</sup>

## 4) ERC-1271-Replay über Accounts/Chains hinweg (fehlende Domain Separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Das Wiederherstellen über einen Raw-Hash ermöglicht Replay über verschiedene Accounts oder Chains hinweg.<sup>[[1]](#references)</sup>

Verwende EIP-712 Typed Data (die Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg den exakten ERC-1271 Magic Value `0x1626ba7e` zurück.<sup>[[1]](#references)</sup>

## 5) Reverts erstatten nach der Validierung keine Gebühren
Sobald `validateUserOp` erfolgreich ist, sind die Gebühren verbindlich, selbst wenn die Ausführung später revertiert. Angreifer können wiederholt Ops einreichen, die fehlschlagen werden, und trotzdem Gebühren vom Account einziehen.<sup>[[1]](#references)</sup>

Bei Paymasters ist es fragil, in `validateUserOp` aus einem gemeinsamen Pool zu zahlen und Nutzer in `postOp` zu belasten, da `postOp` revertieren kann, ohne die Zahlung rückgängig zu machen. Sichere die Mittel während der Validierung (ein Escrow/Deposit pro Nutzer), halte `postOp` minimal und non-reverting und plane `paymasterPostOpGasLimit` für den schlimmsten Fall der Erstattung ein.<sup>[[1]](#references)</sup>

## 6) Counterfactual Deployment / Factory-Annahmen
Die erste `UserOperation` enthält häufig `initCode`, wodurch der Account während der Validierung über eine **Factory** deployed wird. Dieser Pfad wird leicht unzureichend geprüft, da er nur bei der ersten Nutzung ausgeführt wird.<sup>[[2]](#references)</sup>

Häufige Fehler:

- Die Factory/der Initializer vertraut auf `msg.sender == entryPoint`, aber der ERC-4337-Deployment-Pfad ruft `initCode` **nicht** direkt von `EntryPoint` aus auf.
- Der Salt, der Owner, der Validator oder die Modulkonfiguration ist nicht vollständig an die signierte Absicht gebunden, sodass ein Frontrunner das erste Deployment einholen und die Counterfactual-Adresse mit vom Angreifer kontrollierten Einstellungen belegen kann.
- Die Factory ist nicht idempotent, sodass ein wiederholter First-Use-Ablauf die Wallet unbrauchbar macht, anstatt die bereits erstellte Adresse zurückzugeben.

Sicheres Pattern: Berechne den erwarteten Sender anhand der signierten Deployment-Parameter erneut, mache das Deployment deterministisch (typischerweise mit `CREATE2`) und führe die Initialisierung nur einmal aus.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validierungslogik, die Bundler ablehnen
Validierungscode kann in lokalen Tests korrekt sein und trotzdem in realen Bundlern unbrauchbar werden. Öffentliche Bundler simulieren `validateUserOp()` / `validatePaymasterUserOp()` off-chain und führen vor der Aufnahme häufig ein vollständiges `debug_traceCall(handleOps)` aus.<sup>[[3]](#references)</sup>

Dadurch sind diese Muster innerhalb der Validierung gefährlich:

- Von Blocks abhängige Opcodes wie `TIMESTAMP`, `NUMBER` oder `BLOCKHASH`
- State Writes wie `SSTORE`
- Unbegrenzte Iteration über den Storage
- Beliebige externe Calls oder Oracle-Abfragen, die sich zwischen Simulation und Aufnahme ändern können

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
Behandle die Validierung als eine deterministische, begrenzte Preflight-Funktion. Wenn du tatsächlich gemeinsamen Zustand oder externe Abfragen benötigst, verlagere diese Komplexität in gestakte/reputationsverfolgte Entitäten und teste den exakten Bundler-Simulationspfad, nicht nur Unit-Tests.

## 8) ERC-7702 initialization frontrun
ERC-7702 ermöglicht es einer EOA, den Code eines Smart Accounts für eine einzelne Tx auszuführen. Wenn die Initialisierung extern aufrufbar ist, kann ein Frontrunner sich selbst als Owner festlegen.<sup>[[1]](#references)</sup>

Mitigation: Erlaube die Initialisierung nur bei einem **self-call** und nur einmal.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Schnelle Checks vor dem Mergen
- Signaturen mithilfe von `EntryPoint`'s `userOpHash` validieren (bindet Gas-Felder).
- Privilegierte Funktionen je nach Bedarf auf `EntryPoint` und/oder `address(this)` beschränken.
- `validateUserOp` zustandslos und deterministisch halten sowie mit den Simulation Rules des Bundlers kompatibel gestalten.
- Die EIP-712 Domain Separation für ERC-1271 durchsetzen und bei Erfolg `0x1626ba7e` zurückgeben.
- `postOp` minimal, begrenzt und nicht revertierend halten; Gebühren während der Validierung absichern.
- Den ersten `initCode`-Pfad separat testen: deterministische Bereitstellung, idempotentes Factory-Verhalten und einmalige Initialisierung.
- Vor dem Release eine vollständige Bundler-Simulation ausführen (`simulateValidation` plus ein getracetes `handleOps`).
- Für ERC-7702 die Initialisierung nur bei einem Self-Call und nur einmal zulassen.

## Referenzen

- [1] [Six mistakes in ERC-4337 smart accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Account Abstraction Validation Scope Rules](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
