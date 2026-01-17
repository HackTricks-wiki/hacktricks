# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Eine Cold-Wallet-Diebstahlkette kombinierte eine **Supply-Chain-Kompromittierung der Safe{Wallet} Web-UI** mit einer **on-chain delegatecall-Primitive, die den Implementierungszeiger (Slot 0) eines Proxys überschrieb**. Die wichtigsten Erkenntnisse sind:

- Wenn eine dApp Code in den Signing-Pfad injizieren kann, kann sie einen Signer dazu bringen, eine gültige **EIP-712-Signatur über vom Angreifer gewählte Felder** zu erzeugen, während die ursprünglichen UI-Daten wiederhergestellt werden, sodass andere Signer nichts bemerken.
- Safe-Proxys speichern `masterCopy` (Implementation) in **storage slot 0**. Ein delegatecall zu einem Vertrag, der in Slot 0 schreibt, "upgradet" den Safe effektiv auf Angreifer-Logik und verschafft so vollständige Kontrolle über die Wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff selektiv bestimmte Safe- + Signer-Adressen an. Die injizierte Logik wurde unmittelbar vor dem Signing-Aufruf ausgeführt:
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
### Angriffseigenschaften
- **Context-gated**: hartkodierte Allowlists für Opfer-Safes/Signierer verhinderten „Rauschen“ und reduzierten die Entdeckungswahrscheinlichkeit.
- **Last-moment mutation**: Felder (`to`, `data`, `operation`, gas) wurden unmittelbar vor `signTransaction` überschrieben und danach wiederhergestellt, sodass die Proposal-Payloads in der UI harmlos wirkten, während die Signaturen zum Angreifer-Payload passten.
- **EIP-712-Intransparenz**: Wallets zeigten strukturierte Daten, dekodierten aber keine verschachtelte calldata und hoben `operation = delegatecall` nicht hervor, wodurch die mutierte Nachricht effektiv blind-gesigned wurde.

### Relevanz der Gateway-Validierung
Safe proposals werden an das **Safe Client Gateway** übermittelt. Vor den verstärkten Prüfungen konnte das Gateway eine Proposal akzeptieren, bei dem `safeTxHash`/Signatur anderen Feldern als dem JSON-Body entsprachen, falls die UI diese nach dem Signieren umschrieb. Nach dem Vorfall lehnt das Gateway nun Proposals ab, deren Hash/Signatur nicht mit der eingereichten Transaktion übereinstimmen. Eine ähnliche serverseitige Hash-Verifikation sollte für jede Signing-Orchestrierungs-API durchgesetzt werden.

## On-chain: Delegatecall Proxy-Übernahme durch Slot-Kollision

Safe-Proxies halten `masterCopy` in **storage slot 0** und delegieren jegliche Logik dorthin. Da Safe **`operation = 1` (delegatecall)** unterstützt, kann jede signierte Transaktion auf einen beliebigen Vertrag zeigen und dessen Code im Speicher-Kontext des Proxys ausführen.

Ein Angreifervertrag imitierte ein ERC-20 `transfer(address,uint256)`, schrieb aber stattdessen `_to` in Slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ausführungspfad:
1. Opfer signieren `execTransaction` mit `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` validiert Signaturen über diese Parameter.
3. Proxy führt `delegatecall` in `attackerContract` aus; der `transfer`-Body schreibt in slot 0.
4. Slot 0 (`masterCopy`) zeigt nun auf angreiferkontrollierte Logik → **vollständige Übernahme der Wallet und Abfluss der Gelder**.

## Erkennung & Härtungs-Checkliste

- **UI-Integrität**: JS-Assets pinnen / SRI; Bundle-Diffs überwachen; die Signing-UI als Teil der Vertrauensgrenze behandeln.
- **Sign-time validation**: Hardware-Wallets mit **EIP-712 clear-signing**; `operation` explizit darstellen und verschachtelte calldata decodieren. Signing ablehnen, wenn `operation = 1`, sofern die Richtlinie dies nicht erlaubt.
- **Server-side hash checks**: Gateways/Services, die Vorschläge weiterleiten, müssen `safeTxHash` neu berechnen und prüfen, dass die Signaturen mit den eingereichten Feldern übereinstimmen.
- **Policy/allowlists**: Preflight-Regeln für `to`, Selektoren, Asset-Typen und `delegatecall` verbieten, außer für geprüfte Flows. Vor dem Broadcast vollständig signierter Transaktionen einen internen Policy-Service verlangen.
- **Contract design**: Arbiträre `delegatecall` in multisig/treasury wallets vermeiden, sofern nicht strikt erforderlich. Upgrade-Pointer nicht in slot 0 platzieren oder mit expliziter Upgrade-Logik und Access Control absichern.
- **Monitoring**: Alerts bei `delegatecall`-Ausführungen von Wallets mit Treasury-Fonds sowie bei Vorschlägen, die `operation` von typischen `call`-Mustern abändern.

## Referenzen

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
