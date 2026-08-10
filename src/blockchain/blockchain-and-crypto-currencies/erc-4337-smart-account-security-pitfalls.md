# Sicherheitsfallen bei Smart Accounts nach ERC-4337

Die Kontenabstraktion nach ERC-4337 verwandelt Wallets in programmierbare Systeme. Der zentrale Ablauf folgt dem Muster **validate-then-execute** über ein gesamtes Bundle hinweg: Der `EntryPoint` validiert jede `UserOperation`, bevor er eine davon ausführt.<sup>[[5]](#references)</sup> Diese Reihenfolge schafft eine nicht offensichtliche Angriffsfläche, wenn die Validierung permissiv, zustandsbehaftet oder nicht mit den Simulationsregeln des Bundlers konsistent ist.

## 1) Umgehung privilegierter Funktionen durch direkte Aufrufe
Jede extern aufrufbare `execute`-Funktion (oder Funktion zum Verschieben von Geldern), die nicht auf `EntryPoint` (oder ein geprüftes Executor-Modul) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: Auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Self-Management-Flows (Modulinstallation, Validatoränderungen, Upgrades) verwenden.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nicht signierte oder ungeprüfte Gas-Felder -> Gebührenabfluss
Wenn die Signaturvalidierung nur die Absicht (`callData`), nicht aber gasbezogene Felder abdeckt, kann ein bundler oder frontrunner die Gebühren erhöhen und ETH abziehen. Die signierte Payload muss mindestens Folgendes binden:<sup>[[2]](#references)</sup>

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
## 3) Überschreiben des stateful Validation-Zustands (Bundle-Semantik)
Da alle Validierungen vor jeder Ausführung erfolgen, ist das Speichern von Validation-Ergebnissen im Contract-Zustand unsicher. Eine andere Op im selben Bundle kann diesen Zustand überschreiben, sodass deine Ausführung zustandsbasierte, vom Angreifer beeinflusste Werte verwendet.<sup>[[2]](#references)</sup>

Vermeide das Schreiben in den Storage innerhalb von `validateUserOp`. Falls unvermeidbar, indexiere temporäre Daten anhand von `userOpHash` und lösche sie nach der Verwendung deterministisch (bevorzuge stateless Validation).<sup>[[2]](#references)</sup>

## 4) ERC-1271-Replay über Accounts und Chains hinweg (fehlende Domain Separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Die Wiederherstellung über einen rohen Hash ermöglicht Replay-Angriffe über verschiedene Accounts oder Chains hinweg.<sup>[[1]](#references)[[4]](#references)</sup>

Verwende typisierte EIP-712-Daten (die Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg den exakten ERC-1271-Magic-Value `0x1626ba7e` zurück.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Reverts führen nach der Validation nicht zu Rückerstattungen
Sobald `validateUserOp` erfolgreich ist, werden Gebühren festgeschrieben, selbst wenn die Ausführung später revertiert. Angreifer können wiederholt Ops einreichen, die fehlschlagen werden, und trotzdem Gebühren vom Account einziehen.<sup>[[2]](#references)</sup>

Bei Paymasters ist die Zahlung aus einem gemeinsamen Pool in `validateUserOp` und die Belastung der Nutzer in `postOp` problematisch, da `postOp` revertieren kann, ohne die Zahlung rückgängig zu machen. Sichere die Mittel während der Validation (pro Nutzer über Escrow/Deposit), halte `postOp` minimal und non-reverting und plane `paymasterPostOpGasLimit` für den Worst-Case-Erstattungspfad ein.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual Deployment / Annahmen über die Factory
Die erste `UserOperation` enthält häufig `initCode`, wodurch der Account während der Validation über eine **Factory** deployed wird. Dieser Pfad wird leicht unzureichend auditiert, da er nur bei der ersten Verwendung ausgeführt wird.<sup>[[5]](#references)</sup>

Häufige Fehler umfassen:<sup>[[5]](#references)</sup>

- Die Factory bzw. der Initializer vertraut auf `msg.sender == entryPoint`, aber der ERC-4337-Deployment-Pfad ruft `initCode` **nicht** direkt von `EntryPoint` aus auf.
- Der Salt, der Owner, der Validator oder die Module-Konfiguration sind nicht vollständig an die signierte Absicht gebunden, sodass ein Frontrunner das erste Deployment race’n und die counterfactual Adresse mit vom Angreifer kontrollierten Einstellungen belegen kann.
- Die Factory ist nicht idempotent, sodass ein wiederholter First-Use-Ablauf die Wallet unbrauchbar macht, statt die bereits erstellte Adresse zurückzugeben.

Sicheres Muster: Berechne den erwarteten Sender aus den signierten Deployment-Parametern neu, mache das Deployment deterministisch (typischerweise mit `CREATE2`) und führe die Initialisierung nur einmal aus.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validierungslogik, die Bundler ablehnen

Validierungscode kann in lokalen Tests korrekt sein und dennoch in realen Bundlern unbrauchbar sein. Bundler führen die Validierung mehrfach aus und sollten vor der Übermittlung eine vollständige Validierung des Bundles mittels Tracing durchführen.<sup>[[6]](#references)</sup>

Unter diesen Regeln zum Validierungsumfang sind die folgenden Muster gefährlich:<sup>[[6]](#references)</sup>

- Von Blockdaten abhängige Opcodes wie `TIMESTAMP`, `NUMBER` oder `BLOCKHASH`
- Speicherzugriffe außerhalb des zulässigen Account-/Entity-Umfangs oder unbegrenzte Iteration über den Speicher
- Externe Aufrufe oder Oracle-Abfragen, die von veränderlichem Zustand außerhalb des zulässigen Validierungsumfangs abhängen

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
Behandle die Validierung als eine deterministische, begrenzte Preflight-Funktion. Wenn gemeinsamer Zustand oder externe Abfragen erforderlich sind, befolge die Regeln für gestakte Entitäten und teste denselben Multi-Pass-Bundler-Simulationspfad, nicht nur Unit-Tests.<sup>[[6]](#references)</sup>

## 8) ERC-7702-Initialisierungs-Frontrun
ERC-7702 gibt einer EOA eine dauerhafte Delegation an Smart-Account-Code; die Delegation führt die Initialisierung nicht atomar aus. Wenn die Initialisierung extern aufrufbar ist, kann ein Beobachter sie front-runnen und sich selbst als Besitzer festlegen.<sup>[[7]](#references)</sup>

Mitigation: Fordere, dass die Initialisierungs-Calldata von der EOA autorisiert wird, und erlaube die Initialisierung nur einmal. Beschränke in einem ERC-4337-EIP-7702-Flow außerdem den Aufrufer auf `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Schnelle Prüfungen vor dem Merge
- Signaturen mit `EntryPoint`'s `userOpHash` validieren (bindet Gasfelder).
- Privilegierte Funktionen je nach Bedarf auf `EntryPoint` und/oder `address(this)` beschränken.
- `validateUserOp` zustandslos und deterministisch halten sowie mit den Simulationsregeln des Bundlers kompatibel gestalten.
- EIP-712 domain separation für ERC-1271 durchsetzen und bei Erfolg `0x1626ba7e` zurückgeben.
- `postOp` minimal, begrenzt und nicht-revertierend halten; Gebühren während der Validierung absichern.
- Den ersten `initCode`-Pfad separat testen: deterministische Bereitstellung, idempotentes Factory-Verhalten und einmalige Initialisierung.
- Vor der Veröffentlichung die Multi-Pass-Validierung des Bundlers und eine vollständige Traced-Bundle-Prüfung ausführen.
- Für ERC-7702 die Initialisierung an die EOA-Autorisierung binden und nur einmal zulassen; in ERC-4337-Flows den Caller auf `EntryPoint.senderCreator()` beschränken.

## References

- [1] [ERC1271 Replay - 15+ betroffene Teams (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Sechs Fehler bei ERC-4337 Smart Accounts (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardmethode zur Signaturvalidierung für Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing und Signieren typisierter strukturierter Daten](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction mit Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Regeln für den Validierungsbereich von Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Code für EOAs setzen](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
