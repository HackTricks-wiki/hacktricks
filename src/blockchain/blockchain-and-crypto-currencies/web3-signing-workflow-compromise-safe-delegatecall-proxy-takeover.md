# Kompromittierung des Web3-Signing-Workflows & Übernahme eines Safe-Delegatecall-Proxys

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Eine Diebstahlkette aus einer Cold-Wallet kombinierte eine **Supply-Chain-Kompromittierung der Safe{Wallet}-Web-UI** mit einem **On-Chain-Delegatecall-Primitive, das den Implementation Pointer eines Proxys (Slot 0) überschrieb**. Die wichtigsten Erkenntnisse sind:

- Wenn eine dApp Code in den Signing-Pfad einschleusen kann, kann sie einen Signer dazu bringen, eine gültige **EIP-712-Signatur über vom Angreifer gewählte Felder**<sup>[[4]](#references)</sup> zu erzeugen, während sie die ursprünglichen UI-Daten wiederherstellt, sodass andere Signer nichts bemerken.
- Safe-Proxys speichern `masterCopy` (die Implementation) in **Storage-Slot 0**. Ein Delegatecall an einen Contract, der in Slot 0 schreibt, „upgradet“ den Safe effektiv auf die Logik des Angreifers und verschafft ihm vollständige Kontrolle über die Wallet.

## Off-chain: Gezielte Signing-Manipulation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff selektiv bestimmte Safe- und Signer-Adressen an. Die eingeschleuste Logik wurde unmittelbar vor dem Signing-Call ausgeführt:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Kontextabhängig**: Fest codierte Allowlists für die betroffenen Safes/Signer verhinderten Rauschen und senkten die Erkennungswahrscheinlichkeit.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutation im letzten Moment**: Felder (`to`, `data`, `operation`, gas) wurden unmittelbar vor `signTransaction` überschrieben und anschließend zurückgesetzt, sodass Proposal-Payloads in der UI harmlos aussahen, während die Signaturen mit dem Payload des Angreifers übereinstimmten.
- **EIP-712-Intransparenz**: Wallets zeigten strukturierte Daten an, dekodierten jedoch keine verschachtelten Calldata und hoben `operation = delegatecall` nicht hervor, wodurch die mutierte Nachricht effektiv blind signiert wurde.

### Relevanz der Gateway-Validierung
Safe-Proposals werden an das **Safe Client Gateway** übermittelt.<sup>[[5]](#references)</sup> Vor der Einführung härterer Checks konnte das Gateway ein Proposal akzeptieren, bei dem `safeTxHash`/Signatur anderen Feldern entsprachen als denen im JSON-Body, wenn die UI diese nach dem Signieren umschrieb. Nach dem Incident weist das Gateway nun Proposals zurück, deren Hash/Signatur nicht mit der übermittelten Transaktion übereinstimmt. Eine vergleichbare serverseitige Hash-Verifizierung sollte für jede Signing-Orchestration-API erzwungen werden.

### Die wichtigsten Punkte zum Bybit/Safe-Incident von 2025
- Der Drain der Bybit-Cold-Wallet am 21. Februar 2025 (~401k ETH) verwendete dasselbe Muster: Ein kompromittiertes Safe-S3-Bundle wurde nur für Bybit-Signer ausgelöst und änderte `operation=0` → `1`; anschließend zeigte `to` auf einen vorab bereitgestellten Angreifer-Contract, der Slot 0 beschreibt.<sup>[[1]](#references)[[3]](#references)</sup>
- Das aus dem Wayback-Cache stammende `_app-52c9031bfa03da47.js` zeigt, dass die Logik anhand von Bybits Safe (`0x1db9…cf4`) und den Signer-Adressen aktiviert wurde und unmittelbar zwei Minuten nach der Ausführung auf ein sauberes Bundle zurückgesetzt wurde, was den Trick „mutate → sign → restore“ widerspiegelt.<sup>[[1]](#references)[[2]](#references)</sup>
- Der bösartige Contract (z. B. `0x9622…c7242`) enthielt einfache Funktionen `sweepETH/sweepERC20` sowie eine `transfer(address,uint256)`-Funktion, die in den Implementation-Slot schreibt. Die Ausführung von `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` änderte die Proxy-Implementation und gewährte vollständige Kontrolle.<sup>[[1]](#references)[[3]](#references)</sup>

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
1. Opfer signieren `execTransaction` mit `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validiert Signaturen über diese Parameter.
3. Proxy führt einen delegatecall in `attackerContract` aus; der `transfer`-Body schreibt in Slot 0.
4. Slot 0 (`masterCopy`) zeigt nun auf eine vom Angreifer kontrollierte Logik → **vollständige wallet takeover und fund drain**.

### Guard- und Versionshinweise (Hardening nach dem Vorfall)
- Safes >= v1.3.0 können einen **Guard** installieren, um `delegatecall` abzulehnen oder ACLs für `to`/Selectoren durchzusetzen; Bybit verwendete v1.1.1, daher war kein Guard-Hook vorhanden. Ein Upgrade der Contracts (und das erneute Hinzufügen der Owner) ist erforderlich, um diese Kontrollinstanz zu erhalten.

## Checkliste für Detection und Hardening

- **UI-Integrität**: JS-Assets / SRI festschreiben; Bundle-Diffs überwachen; die Signing-UI als Teil der Vertrauensgrenze behandeln.
- **Validierung zum Signierzeitpunkt**: Hardware-Wallets mit **EIP-712 clear-signing**; `operation` explizit anzeigen und verschachtelte Calldata decodieren. Das Signieren ablehnen, wenn `operation = 1` ist, sofern die Policy dies nicht erlaubt.
- **Hash-Prüfungen auf der Serverseite**: Gateways/Services, die Proposals weiterleiten, müssen `safeTxHash` neu berechnen und validieren, dass die Signaturen mit den übermittelten Feldern übereinstimmen.
- **Policies/Allowlists**: Preflight-Regeln für `to`, Selectoren und Asset-Typen; delegatecall nur bei überprüften Flows erlauben. Vor dem Broadcasting vollständig signierter Transaktionen einen internen Policy-Service verlangen.
- **Contract-Design**: Das Bereitstellen beliebiger delegatecall-Funktionen in Multisig-/Treasury-Wallets vermeiden, sofern dies nicht unbedingt erforderlich ist. Upgrade-Pointer außerhalb von Slot 0 platzieren oder mit expliziter Upgrade-Logik und Access Control absichern.
- **Monitoring**: Bei delegatecall-Ausführungen aus Wallets mit Treasury-Funds sowie bei Proposals, die `operation` gegenüber üblichen `call`-Mustern ändern, einen Alert auslösen.

## Referenzen

- [1] [Forensische Analyse des Bybit-Safe-Exploits von AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analyse des Safe-Bundle-Compromises von Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaillierte technische Analyse des Bybit-Hacks (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
