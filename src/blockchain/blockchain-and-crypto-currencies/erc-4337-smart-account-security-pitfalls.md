# Sicherheitsrisiken bei ERC-4337 Smart Accounts

{{#include ../../banners/hacktricks-training.md}}

ERC-4337-Kontoabstraktion verwandelt Wallets in programmierbare Systeme. Der zentrale Ablauf folgt dem Muster **validate-then-execute** über ein gesamtes Bundle: Der `EntryPoint` validiert jede `UserOperation`, bevor eine davon ausgeführt wird.<sup>[[5]](#references)</sup> Diese Reihenfolge schafft eine nicht offensichtliche Angriffsfläche, wenn die Validierung zu permissiv oder zustandsbehaftet ist oder nicht mit den Simulationsregeln des Bundlers übereinstimmt.

## 1) Umgehung privilegierter Funktionen durch direkte Aufrufe
Jede extern aufrufbare `execute`-Funktion (oder Funktion zum Transferieren von Geldern), die nicht auf `EntryPoint` (oder ein geprüftes Executor-Modul) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Self-Management-Abläufe (Modulinstallation, Validatoränderungen, Upgrades) verwenden.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nicht signierte oder ungeprüfte Gas-Felder -> Gebührenabfluss
Wenn die Signaturvalidierung nur die Absicht (`callData`), nicht aber gasbezogene Felder abdeckt, kann ein Bundler oder Frontrunner die Gebühren erhöhen und ETH abziehen. Das signierte Payload muss mindestens Folgendes binden:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensives Muster: Verwende den von `EntryPoint` bereitgestellten `userOpHash` (der Gas-Felder enthält) und/oder begrenze jedes Feld strikt.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Überschreiben des Stateful-Validierungsstatus (Bundle-Semantik)
Da alle Validierungen vor jeder Ausführung erfolgen, ist das Speichern von Validierungsergebnissen im Contract-State unsicher. Eine andere Op im selben Bundle kann diesen Wert überschreiben, wodurch deine Ausführung einen vom Angreifer beeinflussten State verwendet.<sup>[[2]](#references)</sup>

Vermeide das Schreiben in den Storage in `validateUserOp`. Falls unvermeidbar, müssen temporäre Daten über `userOpHash` adressiert und nach der Verwendung deterministisch gelöscht werden (bevorzuge stateless validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271-Replay über Accounts/Chains hinweg (fehlende Domain Separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Das Wiederherstellen über einen rohen Hash ermöglicht das Replay von Signaturen über verschiedene Accounts oder Chains hinweg.<sup>[[1]](#references)[[4]](#references)</sup>

Verwende EIP-712-Typed Data (die Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg den exakten ERC-1271-Magic Value `0x1626ba7e` zurück.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts erstatten nach der Validierung keine Gebühren
Sobald `validateUserOp` erfolgreich ist, sind die Gebühren festgeschrieben, selbst wenn die Ausführung später revertiert. Angreifer können wiederholt Ops einreichen, die fehlschlagen werden, und trotzdem Gebühren vom Account einziehen.<sup>[[2]](#references)</sup>

Bei Paymasters ist die Zahlung aus einem gemeinsam genutzten Pool in `validateUserOp` und die Abrechnung der Nutzer in `postOp` problematisch, da `postOp` revertieren kann, ohne die Zahlung rückgängig zu machen. Sichere die Mittel während der Validierung (benutzerbezogenes Escrow/Deposit), halte `postOp` minimal und non-reverting und plane `paymasterPostOpGasLimit` für den Worst-Case-Erstattungspfad ausreichend hoch ein.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual Deployment / Factory-Annahmen
Die erste `UserOperation` enthält häufig `initCode`, wodurch der Account während der Validierung über eine **Factory** deployed wird. Dieser Pfad wird leicht unzureichend geprüft, da er nur bei der ersten Verwendung ausgeführt wird.<sup>[[5]](#references)</sup>

Häufige Fehler sind:<sup>[[5]](#references)</sup>

- Die Factory/der Initializer vertraut auf `msg.sender == entryPoint`, aber der ERC-4337-Deployment-Pfad ruft `initCode` **nicht** direkt von `EntryPoint` aus auf.
- Der Salt, der Owner, der Validator oder die Modulkonfiguration ist nicht vollständig an die signierte Absicht gebunden, sodass ein Front-runner mit angreiferkontrollierten Einstellungen die erste Bereitstellung überholen und die counterfactual address belegen kann.
- Die Factory ist nicht idempotent, sodass ein wiederholter First-Use-Flow die Wallet unbrauchbar macht, anstatt die bereits erstellte Adresse zurückzugeben.

Sicheres Muster: Berechne den erwarteten Sender aus den signierten Deployment-Parametern neu, mache das Deployment deterministisch (typischerweise mit `CREATE2`) und führe die Initialisierung nur einmal aus.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validierungslogik, die Bundler ablehnen

Validierungscode kann in lokalen Tests korrekt sein und dennoch in realen Bundlern unbrauchbar sein. Bundler führen die Validierung mehrfach aus und sollten vor der Übermittlung eine vollständige Validierung des nachverfolgten Bundles durchführen.<sup>[[6]](#references)</sup>

Unter diesen Regeln für den Validierungsumfang sind folgende Muster gefährlich:<sup>[[6]](#references)</sup>

- Von Blockdaten abhängige Opcodes wie `TIMESTAMP`, `NUMBER` oder `BLOCKHASH`
- Speicherzugriffe außerhalb des zulässigen Account-/Entity-Umfangs oder unbegrenzte Iteration über den Speicher
- Externe Aufrufe oder Oracle-Lesevorgänge, die von veränderlichem State außerhalb des zulässigen Validierungsumfangs abhängen

Schlechtes Beispiel:
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
Behandle die Validierung als deterministische, begrenzte Preflight-Funktion. Wenn gemeinsamer State oder externe Lookups erforderlich sind, befolge die Regeln für gestakete Entitäten und teste denselben Multi-Pass-Bundler-Simulationspfad, nicht nur Unit-Tests.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 gibt einer EOA eine persistente Delegation an Smart-Account-Code; die Delegation führt die Initialisierung nicht atomar aus. Wenn die Initialisierung extern aufrufbar ist, kann ein Beobachter sie front-runnen und sich selbst als Owner festlegen.<sup>[[7]](#references)</sup>

Abhilfe: Verlange, dass die Initialisierungs-`calldata` von der EOA autorisiert wird, und erlaube die Initialisierung nur einmal. Beschränke in einem ERC-4337-EIP-7702-Flow den Aufrufer außerdem auf `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Schnelle Prüfungen vor dem Mergen
- Signaturen mit dem `userOpHash` von `EntryPoint` validieren (bindet Gasfelder).
- Privilegierte Funktionen, sofern angemessen, auf `EntryPoint` und/oder `address(this)` beschränken.
- `validateUserOp` zustandslos, deterministisch und mit den Simulationsregeln des Bundlers kompatibel halten.
- Die EIP-712-Domain-Separation für ERC-1271 durchsetzen und bei Erfolg `0x1626ba7e` zurückgeben.
- `postOp` minimal, begrenzt und nicht revertierend halten; Gebühren während der Validierung absichern.
- Den ersten `initCode`-Pfad separat testen: deterministische Bereitstellung, idempotentes Factory-Verhalten und einmalige Initialisierung.
- Vor dem Release die Multi-Pass-Validierung des Bundlers und eine nachverfolgte Prüfung des vollständigen Bundles ausführen.
- Für ERC-7702 die Initialisierung an die EOA-Autorisierung binden und nur einmal zulassen; in ERC-4337-Flows den Aufrufer auf `EntryPoint.senderCreator()` beschränken.

## References

- [1] [ERC1271 Replay - Mehr als 15 Teams betroffen (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sechs Fehler bei ERC-4337-Smart Accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardmethode zur Signaturvalidierung für Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing und Signieren typisierter strukturierter Daten](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction unter Verwendung eines alternativen Mempools](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Regeln für den Validierungsbereich von Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Code für EOAs setzen](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
