# Kompromittierung des Web3-Signing-Workflows & Übernahme durch Safe Delegatecall Proxy

## Überblick

Eine cold-wallet theft chain kombinierte eine **supply-chain compromise der Safe{Wallet}-Web-UI** mit einem **on-chain delegatecall primitive, das den implementation pointer eines Proxys (slot 0) überschrieb**. Die wichtigsten Erkenntnisse sind:

- Wenn eine dApp Code in den Signing-Pfad einschleusen kann, kann sie einen Signer dazu bringen, eine gültige **EIP-712-Signatur über vom Angreifer gewählte Felder** zu erzeugen und gleichzeitig die ursprünglichen UI-Daten wiederherzustellen, sodass andere Signer nichts bemerken.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe-Proxys speichern `masterCopy` (implementation) in **storage slot 0**. Ein delegatecall an einen Contract, der in slot 0 schreibt, „upgradet“ den Safe effektiv auf die Logik des Angreifers und verschafft ihm vollständige Kontrolle über die Wallet.<sup>[[3]](#references)</sup>

## Off-chain: Gezielte Signing-Mutation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff gezielt bestimmte Safe- und Signer-Adressen an. Die eingeschleuste Logik wurde unmittelbar vor dem Signing-Call ausgeführt:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Kontextgesteuert**: Hartcodierte Allowlists für betroffene Safes/Signer verhinderten Rauschen und senkten die Erkennungswahrscheinlichkeit.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mutation im letzten Moment**: Felder (`to`, `data`, `operation`, Gas) wurden unmittelbar vor `signTransaction` überschrieben und anschließend zurückgesetzt, sodass Proposal-Payloads in der UI harmlos aussahen, während die Signaturen mit der Angreifer-Payload übereinstimmten.<sup>[[3]](#references)</sup>
- **EIP-712-Intransparenz**: Wallets zeigten strukturierte Daten an, decodierten jedoch keine verschachtelten Calldata und hoben `operation = delegatecall` nicht hervor, wodurch die mutierte Nachricht effektiv blind signiert wurde.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevanz der Gateway-Validierung
Safe-Proposals werden an das **Safe Client Gateway** übermittelt.<sup>[[5]](#references)</sup> Vor der Einführung verschärfter Prüfungen konnte das Gateway ein Proposal akzeptieren, bei dem `safeTxHash`/Signatur anderen Feldern entsprach als der JSON-Body, wenn die UI diese nach dem Signieren umschrieb. Nach dem Vorfall lehnt das Gateway nun Proposals ab, deren Hash/Signatur nicht mit der übermittelten Transaktion übereinstimmt.<sup>[[3]](#references)</sup> Eine ähnliche serverseitige Hash-Verifizierung sollte für jede Signing-Orchestration-API erzwungen werden.

### Die wichtigsten Punkte des Bybit/Safe-Vorfalls von 2025
- Der Drain der Bybit-Cold-Wallet am 21. Februar 2025 (~401k ETH) nutzte dasselbe Muster: Ein kompromittiertes Safe-S3-Bundle wurde nur für Bybit-Signer ausgelöst und änderte `operation=0` → `1`, wobei `to` auf einen vorab bereitgestellten Angreifer-Contract zeigte, der Slot 0 beschreibt.<sup>[[1]](#references)[[3]](#references)</sup>
- Das im Wayback-Archiv zwischengespeicherte `_app-52c9031bfa03da47.js` zeigt, dass die Logik anhand von Bybits Safe (`0x1db9…cf4`) und den Signer-Adressen aktiviert wurde und anschließend zwei Minuten nach der Ausführung sofort auf ein sauberes Bundle zurückgesetzt wurde – analog zum Trick „mutate → sign → restore“.<sup>[[1]](#references)[[2]](#references)</sup>
- Der schädliche Contract (z. B. `0x9622…c7242`) enthielt einfache Funktionen `sweepETH/sweepERC20` sowie eine `transfer(address,uint256)`-Funktion, die den Implementation-Slot beschreibt. Die Ausführung von `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` änderte die Proxy-Implementierung und gewährte vollständige Kontrolle.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Übernahme eines Delegatecall-Proxys durch Slot-Kollision

Safe-Proxys speichern `masterCopy` in **Storage-Slot 0** und delegieren die gesamte Logik dorthin. Da Safe **`operation = 1` (delegatecall)** unterstützt, kann jede signierte Transaktion auf einen beliebigen Contract zeigen und dessen Code im Storage-Kontext des Proxys ausführen.<sup>[[3]](#references)</sup>

Ein Angreifer-Contract ahmte eine ERC-20-`transfer(address,uint256)`-Funktion nach, schrieb jedoch stattdessen `_to` in Slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
3. Der Proxy führt per delegatecall `attackerContract` aus; der `transfer`-Body schreibt in Slot 0.
4. Slot 0 (`masterCopy`) zeigt nun auf eine vom Angreifer kontrollierte Logik → **vollständige Übernahme der Wallet und Abfluss der Gelder**.

### Guard- und Versionshinweise (Härtung nach dem Vorfall)
- Transaction guards wurden in Safe v1.3.0 eingeführt und können vor der Ausführung alle `execTransaction`-Parameter prüfen; ein Guard kann `delegatecall` ablehnen oder Richtlinien für Ziel und Calldata erzwingen. Bybit verwendete v1.1.1, das vor der Einführung dieses Hooks liegt.<sup>[[2]](#references)[[6]](#references)</sup>

## Erkennungs- und Härtungs-Checkliste

- **UI-Integrität**: JS-Assets / SRI pinnen; Bundle-Differenzen überwachen; die Signing-UI als Teil der Vertrauensgrenze behandeln.
- **Validierung zum Signierzeitpunkt**: Hardware-Wallets mit **EIP-712 clear-signing**; `operation` explizit anzeigen und verschachtelte Calldata decodieren. Das Signieren ablehnen, wenn `operation = 1` ist, sofern dies nicht durch die Richtlinie erlaubt wird.<sup>[[3]](#references)</sup>
- **Hash-Prüfungen auf der Serverseite**: Gateways/Services, die Vorschläge weiterleiten, müssen `safeTxHash` neu berechnen und validieren, dass die Signaturen mit den übermittelten Feldern übereinstimmen.<sup>[[3]](#references)</sup>
- **Richtlinien/Allowlists**: Preflight-Regeln für `to`, Selector und Asset-Typen; delegatecall außer bei geprüften Abläufen verbieten. Vor dem Broadcast vollständig signierter Transaktionen einen internen Policy-Service voraussetzen.
- **Contract-Design**: Das Offenlegen beliebiger delegatecall-Funktionen in Multisig-/Treasury-Wallets vermeiden, sofern dies nicht unbedingt erforderlich ist. Jeden Implementation-Pointer als Upgrade-Primitiv behandeln: mit expliziter Zugriffskontrolle absichern und delegatecall-Ziele/-Selectoren durch Guards schützen; das Verschieben des Pointers in einen anderen Slot allein ist keine vollständige Abwehr.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: Bei delegatecall-Ausführungen von Wallets mit Treasury-Geldern sowie bei Vorschlägen alarmieren, die `operation` von typischen `call`-Mustern ändern.

## References

- [1] [Forensische Analyse des Safe-Exploits bei Bybit von AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analyse des Safe-Bundle-Kompromisses von Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaillierte technische Analyse des Bybit-Hacks (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog von Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
