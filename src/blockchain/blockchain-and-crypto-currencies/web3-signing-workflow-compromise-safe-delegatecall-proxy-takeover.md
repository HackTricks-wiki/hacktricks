# Kompromittierung des Web3-Signing-Workflows & Takeover eines Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Eine Cold-Wallet-Diebstahlkette kombinierte eine **Supply-Chain-Kompromittierung der Safe{Wallet}-Weboberfläche** mit einem **On-Chain-Delegatecall-Primitiv, das den Implementation Pointer eines Proxys (Slot 0) überschreibt**. Die wichtigsten Erkenntnisse sind:

- Wenn ein dApp Code in den Signing-Pfad einschleusen kann, kann es einen Signer dazu bringen, eine gültige **EIP-712-Signatur über vom Angreifer gewählte Felder** zu erstellen, während die ursprünglichen UI-Daten wiederhergestellt werden, sodass andere Signer nichts davon bemerken.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe-Proxys speichern `masterCopy` (Implementation) in **Storage Slot 0**. Ein Delegatecall an einen Contract, der in Slot 0 schreibt, „upgradet“ den Safe effektiv auf die Logik des Angreifers und verschafft ihm die vollständige Kontrolle über die Wallet.<sup>[[3]](#references)</sup>

## Off-Chain: Gezielte Signing-Manipulation in Safe{Wallet}

Ein manipuliertes Safe-Bundle (`_app-*.js`) griff selektiv bestimmte Safe- und Signer-Adressen an. Die injizierte Logik wurde direkt vor dem Signing-Aufruf ausgeführt:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: Hard-coded-Allowlists für betroffene Safes/Signer verhinderten Rauschen und senkten die Erkennungswahrscheinlichkeit.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: Felder (`to`, `data`, `operation`, gas) wurden unmittelbar vor `signTransaction` überschrieben und anschließend zurückgesetzt, sodass Proposal-Payloads in der UI harmlos aussahen, während die Signaturen mit der Angreifer-Payload übereinstimmten.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: Wallets zeigten strukturierte Daten an, dekodierten jedoch keine verschachtelten Calldata und markierten `operation = delegatecall` nicht hervor, wodurch die mutierte Nachricht effektiv blind signiert wurde.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevanz der Gateway-Validierung
Safe-Proposals werden an das **Safe Client Gateway** übermittelt.<sup>[[5]](#references)</sup> Vor der Einführung gehärteter Prüfungen konnte das Gateway ein Proposal akzeptieren, bei dem `safeTxHash`/Signatur anderen Feldern entsprachen als der JSON-Body, wenn die UI diese nach dem Signieren umschrieb. Nach dem Vorfall weist das Gateway nun Proposals zurück, deren Hash/Signatur nicht mit der übermittelten Transaktion übereinstimmen.<sup>[[3]](#references)</sup> Eine ähnliche serverseitige Hash-Überprüfung sollte für jede Signing-Orchestration-API erzwungen werden.

### Höhepunkte des Bybit/Safe-Vorfalls von 2025
- Der Drain der Bybit-Cold-Wallet am 21. Februar 2025 (~401k ETH) verwendete dasselbe Muster: Ein kompromittiertes Safe-S3-Bundle wurde nur für Bybit-Signer ausgelöst und änderte `operation=0` → `1`, wobei `to` auf einen vorab bereitgestellten Angreifer-Contract zeigte, der Slot 0 beschreibt.<sup>[[1]](#references)[[3]](#references)</sup>
- Das von Wayback gecachte `_app-52c9031bfa03da47.js` zeigt, dass die Logik anhand von Bybits Safe (`0x1db9…cf4`) und den Signer-Adressen ausgelöst wurde und anschließend zwei Minuten nach der Ausführung sofort auf ein sauberes Bundle zurückgesetzt wurde, was den „mutate → sign → restore“-Trick widerspiegelt.<sup>[[1]](#references)[[2]](#references)</sup>
- Der schädliche Contract (z. B. `0x9622…c7242`) enthielt einfache Funktionen `sweepETH/sweepERC20` sowie ein `transfer(address,uint256)`, das in den Implementation-Slot schreibt. Die Ausführung von `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` änderte die Proxy-Implementation und gewährte vollständige Kontrolle.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall-Proxy-Takeover durch Slot-Collision

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
3. Der Proxy führt einen delegatecall zu `attackerContract` aus; der `transfer`-Body schreibt in Slot 0.
4. Slot 0 (`masterCopy`) verweist nun auf vom Angreifer kontrollierte Logik → **vollständige Übernahme des Wallets und Abfluss der Gelder**.

### Guard- und Versionshinweise (Hardening nach dem Vorfall)
- Transaction guards wurden in Safe v1.3.0 eingeführt und können alle `execTransaction`-Parameter vor der Ausführung prüfen; ein Guard kann `delegatecall` ablehnen oder Richtlinien für Ziel und calldata durchsetzen. Bybit verwendete v1.1.1, das vor diesem Hook liegt.<sup>[[2]](#references)[[6]](#references)</sup>

## Erkennungs- und Hardening-Checkliste

- **UI-Integrität**: JS-Assets / SRI pinnen; Bundle-Diffs überwachen; die Signing-UI als Teil der Vertrauensgrenze behandeln.
- **Validierung zum Signierzeitpunkt**: Hardware-Wallets mit **EIP-712 clear-signing**; `operation` explizit anzeigen und verschachtelte calldata decodieren. Das Signieren ablehnen, wenn `operation = 1` gilt, sofern die Richtlinie dies nicht erlaubt.<sup>[[3]](#references)</sup>
- **Hash-Prüfungen auf der Serverseite**: Gateways/Services, die proposals weiterleiten, müssen `safeTxHash` neu berechnen und prüfen, ob die Signaturen mit den übermittelten Feldern übereinstimmen.<sup>[[3]](#references)</sup>
- **Richtlinien/Allowlists**: Preflight-Regeln für `to`, Selector und Asset-Typen sowie `delegatecall` verbieten, außer bei geprüften Abläufen. Vor dem Broadcasting vollständig signierter Transaktionen einen internen Policy-Service voraussetzen.
- **Contract-Design**: Das beliebige Ausführen von delegatecall in Multisig-/Treasury-Wallets vermeiden, sofern es nicht unbedingt erforderlich ist. Jeden Implementation-Pointer als Upgrade-Primitiv behandeln: mit expliziter Zugriffskontrolle schützen und Delegatecall-Ziele/Selectoren absichern; den Pointer allein in einen anderen Slot zu verschieben, ist keine vollständige Abwehr.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: Bei delegatecall-Ausführungen aus Wallets, die Treasury-Gelder halten, sowie bei proposals alarmieren, die `operation` von typischen `call`-Mustern ändern.

## References

- [1] [Forensische Analyse des Bybit-Safe-Exploits von AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analyse des Safe-Bundle-Compromises von Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaillierte technische Analyse des Bybit-Hacks (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
