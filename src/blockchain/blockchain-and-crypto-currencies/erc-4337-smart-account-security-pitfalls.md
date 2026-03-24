# ERC-4337 Smart Account Sicherheitsfallen

{{#include ../../banners/hacktricks-training.md}}

Die ERC-4337 Account-Abstraktion verwandelt Wallets in programmierbare Systeme. Der Kernablauf ist **validate-then-execute** über ein gesamtes Bundle: der `EntryPoint` validiert jede `UserOperation`, bevor er eine von ihnen ausführt. Diese Reihenfolge schafft nicht offensichtliche Angriffsflächen, wenn die Validierung zu großzügig oder zustandsbehaftet ist.

## 1) Umgehung privilegierter Funktionen durch Direktaufrufe
Jede extern aufrufbare `execute` (oder funds-moving) Funktion, die nicht auf `EntryPoint` (oder ein geprüftes executor module) beschränkt ist, kann direkt aufgerufen werden, um das Konto zu leeren.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Sicheres Muster: auf `EntryPoint` beschränken und `msg.sender == address(this)` für Admin-/Selbstverwaltungsabläufe verwenden (Modul-Installation, Validator-Änderungen, Upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nicht signierte oder ungeprüfte Gas-Felder -> Gebührenabfluss
Wenn die Signaturvalidierung nur die Absicht (`callData`) abdeckt, aber nicht gasbezogene Felder, kann ein bundler oder frontrunner die Gebühren aufblasen und ETH abziehen. Die signierte Payload muss mindestens folgende Felder binden:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Absicherungsmuster: Verwende den von `EntryPoint` bereitgestellten `userOpHash` (der die gasbezogenen Felder einschließt) und/oder begrenze jedes Feld strikt.
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
Weil alle Validierungen vor der Ausführung laufen, ist es unsicher, Validierungsergebnisse im Contract-State zu speichern. Eine andere op im selben Bundle kann sie überschreiben, sodass deine Ausführung Zustand verwendet, der von einem Angreifer beeinflusst wurde.

Vermeide Schreibzugriffe auf Storage in `validateUserOp`. Falls unvermeidlich, indiziere temporäre Daten mit `userOpHash` und lösche sie nach Gebrauch deterministisch (bevorzuge zustandslose Validierung).

## 4) ERC-1271 replay across accounts/chains (missing domain separation)
`isValidSignature(bytes32 hash, bytes sig)` muss Signaturen an **diesen Contract** und **diese Chain** binden. Das Recovern über einen rohen Hash ermöglicht Replay von Signaturen über Accounts oder Chains.

Verwende EIP-712 typed data (Domain enthält `verifyingContract` und `chainId`) und gib bei Erfolg den exakten ERC-1271 Magic-Wert `0x1626ba7e` zurück.

## 5) Reverts do not refund after validation
Sobald `validateUserOp` erfolgreich ist, sind Gebühren festgeschrieben, selbst wenn die Ausführung später revertet. Angreifer können wiederholt ops einreichen, die fehlschlagen, und trotzdem Gebühren vom Account einziehen.

Für paymasters ist es fragil, in `validateUserOp` aus einem gemeinsamen Pool zu bezahlen und Nutzer in `postOp` zu belasten, da `postOp` revertieren kann, ohne die Zahlung rückgängig zu machen. Sichere Mittel während der Validierung (per-user escrow/deposit) und halte `postOp` minimal und nicht-revertierend.

## 6) ERC-7702 initialization frontrun
ERC-7702 erlaubt einer EOA, smart-account Code für eine einzelne tx auszuführen. Wenn die Initialisierung extern aufrufbar ist, kann ein Frontrunner sich selbst als Owner setzen.

Abhilfe: Initialisierung nur bei **self-call** und nur einmal erlauben.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Schnelle Pre-Merge-Checks
- Signaturen mit `EntryPoint`'s `userOpHash` validieren (bindet Gas-Felder).
- Privilegierte Funktionen auf `EntryPoint` und/oder `address(this)` beschränken, je nach Bedarf.
- `validateUserOp` zustandslos halten.
- EIP-712 Domain-Separation für ERC-1271 erzwingen und `0x1626ba7e` bei Erfolg zurückgeben.
- `postOp` minimal, begrenzt und nicht revertierend halten; Gebühren während der Validierung sichern.
- Für ERC-7702 init nur bei Selbstaufruf und nur einmal erlauben.

## Referenzen

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
