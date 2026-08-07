# Sicherheitsfallen bei ERC-4337 Smart Accounts

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 Account Abstraction verwandelt Wallets in programmierbare Systeme. Der zentrale Ablauf ist **validate-then-execute** über ein gesamtes Bundle: Der `EntryPoint` validiert jede `UserOperation`, bevor irgendeine davon ausgeführt wird. Diese Reihenfolge schafft eine nicht offensichtliche Angriffsfläche, wenn die Validierung zu permissiv oder zustandsbehaftet ist oder nicht mit den Simulationsregeln des Bundlers übereinstimmt.

## 1) Umgehung privilegierter Funktionen durch direkte Aufrufe
Jede extern aufrufbare `execute`- (oder Geldbewegungs-)Funktion, die nicht auf den `EntryPoint` (oder ein geprüftes Executor-Modul) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Selbstverwaltungsabläufe verwenden (Modulinstallation, Validatoränderungen, Upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nicht signierte oder ungeprüfte Gas-Felder -> Gebührenabfluss
Wenn die Signaturprüfung nur die Intention (`callData`), aber nicht die gasbezogenen Felder abdeckt, kann ein Bundler oder Frontrunner die Gebühren erhöhen und ETH abziehen. Der signierte Payload muss mindestens Folgendes binden:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensives Muster: Verwende den von `EntryPoint` bereitgestellten `userOpHash` (der Gas-Felder einschließt) und/oder begrenze jedes Feld strikt.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering des zustandsbehafteten Validierungsergebnisses (Bundle-Semantik)
Da alle Validierungen vor jeder Ausführung erfolgen, ist das Speichern von Validierungsergebnissen im Contract-State unsicher. Eine andere Op im selben Bundle kann diesen Wert überschreiben, sodass deine Ausführung einen vom Angreifer beeinflussten State verwendet.<sup>[[1]](#references)</sup>

Vermeide das Schreiben in den Storage innerhalb von `validateUserOp`. Falls es unvermeidbar ist, müssen temporäre Daten über `userOpHash` adressiert und nach der Verwendung deterministisch gelöscht werden (zustandslose Validierung ist vorzuziehen).<sup>[[1]](#references)</sup>

## 4) ERC-1271-Replay über Accounts und Chains hinweg (fehlende Domain-Separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Die Wiederherstellung über einen Raw-Hash ermöglicht das Replay von Signaturen über verschiedene Accounts oder Chains hinweg.<sup>[[1]](#references)</sup>

Verwende typisierte EIP-712-Daten (die Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg exakt den ERC-1271-Magic-Value `0x1626ba7e` zurück.<sup>[[1]](#references)</sup>

## 5) Reverts erstatten Gebühren nach der Validierung nicht
Sobald `validateUserOp` erfolgreich ist, sind die Gebühren festgeschrieben, selbst wenn die Ausführung später reverted. Angreifer können wiederholt Ops einreichen, die fehlschlagen werden, und trotzdem Gebühren aus dem Account einziehen.<sup>[[1]](#references)</sup>

Bei Paymasters ist die Zahlung aus einem gemeinsamen Pool in `validateUserOp` und die Abrechnung der Nutzer in `postOp` fragil, da `postOp` reverten kann, ohne die Zahlung rückgängig zu machen. Sichere die Mittel während der Validierung (nutzerbezogenes Escrow/Deposit), halte `postOp` minimal und nicht-revertierend und bemesse `paymasterPostOpGasLimit` für den Worst-Case-Erstattungspfad.<sup>[[1]](#references)</sup>

## 6) Counterfactual Deployment / Annahmen über die Factory
Die erste `UserOperation` enthält häufig `initCode`, wodurch der Account während der Validierung über eine **Factory** deployed wird. Dieser Pfad wird leicht unzureichend auditiert, da er nur bei der ersten Verwendung ausgeführt wird.<sup>[[2]](#references)</sup>

Häufige Fehler:

- Die Factory bzw. der Initializer vertraut auf `msg.sender == entryPoint`, aber der ERC-4337-Deployment-Pfad ruft `initCode` **nicht** direkt von `EntryPoint` aus auf.
- Der Salt, der Owner, der Validator oder die Module-Konfiguration ist nicht vollständig an die signierte Absicht gebunden, sodass ein Frontrunner mit einem Race die erste Deployment-Transaktion gewinnt und die Counterfactual-Adresse mit angreiferkontrollierten Einstellungen belegt.
- Die Factory ist nicht idempotent, sodass ein wiederholter First-Use-Ablauf die Wallet unbrauchbar macht, anstatt die bereits erstellte Adresse zurückzugeben.

Sicheres Muster: Berechne den erwarteten Sender anhand der signierten Deployment-Parameter neu, mache das Deployment deterministisch (typischerweise mit `CREATE2`) und führe die Initialisierung genau einmal aus.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validierungslogik, die bundlers ablehnen

Validierungscode kann in lokalen Tests korrekt funktionieren und trotzdem in echten bundlers unbrauchbar sein. Öffentliche bundlers simulieren `validateUserOp()` / `validatePaymasterUserOp()` off-chain und führen vor der Aufnahme üblicherweise einen vollständigen `debug_traceCall(handleOps)` aus.

Dadurch sind diese Muster innerhalb der Validierung gefährlich:

- Von Blockdaten abhängige Opcodes wie `TIMESTAMP`, `NUMBER` oder `BLOCKHASH`
- State-Schreibvorgänge wie `SSTORE`
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
Behandle die Validierung als eine deterministische, begrenzte Preflight-Funktion. Wenn du tatsächlich gemeinsamen State oder externe Lookups benötigst, verlagere diese Komplexität in gestakte/reputationsüberwachte Entitäten und teste den exakten Bundler-Simulationspfad, nicht nur Unit-Tests.

## 8) ERC-7702-Initialisierungs-Frontrun
ERC-7702 ermöglicht es einer EOA, den Smart-Account-Code für eine einzelne tx auszuführen. Wenn die Initialisierung extern aufrufbar ist, kann ein Frontrunner sich selbst als owner festlegen.<sup>[[1]](#references)</sup>

Mitigation: Erlaube die Initialisierung nur bei einem **self-call** und nur einmal.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Schnelle Checks vor dem Merge
- Signaturen mit dem `userOpHash` von `EntryPoint` validieren (bindet Gas-Felder).
- Privilegierte Funktionen je nach Bedarf auf `EntryPoint` und/oder `address(this)` beschränken.
- `validateUserOp` zustandslos und deterministisch halten sowie mit den Simulationsregeln des Bundlers kompatibel machen.
- EIP-712 Domain-Separation für ERC-1271 erzwingen und bei Erfolg `0x1626ba7e` zurückgeben.
- `postOp` minimal, begrenzt und ohne Reverts halten; Gebühren während der Validierung absichern.
- Den ersten `initCode`-Pfad separat testen: deterministische Deployment, idempotentes Factory-Verhalten und einmalige Initialisierung.
- Vor dem Release eine vollständige Bundler-Simulation ausführen (`simulateValidation` plus ein getracetes `handleOps`).
- Für ERC-7702 die Initialisierung nur bei einem Self-Call und nur einmal erlauben.



## Referenzen

- [1] [Sechs Fehler bei ERC-4337 Smart Accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Account-Abstraktion unter Verwendung eines alternativen Mempools](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
