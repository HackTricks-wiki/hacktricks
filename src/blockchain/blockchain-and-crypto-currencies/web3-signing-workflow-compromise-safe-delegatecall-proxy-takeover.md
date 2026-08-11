# Kompromitovanje Web3 Signing Workflow-a i preuzimanje Safe Delegatecall Proxy-ja

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Lanac krađe iz cold wallet-a kombinovao je **kompromitovanje supply chain-a web UI-ja Safe{Wallet}** sa **on-chain delegatecall primitivom koji je prepisao implementation pointer proxy-ja (slot 0)**. Ključni zaključci su:

- Ako dApp može da ubaci code u signing path, može da navede signera da generiše validan **EIP-712 signature nad poljima koja je izabrao attacker**, dok istovremeno vraća originalne UI podatke kako bi drugi signeri ostali nesvesni.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxy-ji čuvaju `masterCopy` (implementation) u **storage slot-u 0**. Delegatecall ka contract-u koji upisuje u slot 0 praktično „upgrade-uje“ Safe na attacker logic, čime se dobija potpuna kontrola nad wallet-om.<sup>[[3]](#references)</sup>

## Off-chain: Ciljana mutacija signing-a u Safe{Wallet}-u

Izmenjeni Safe bundle (`_app-*.js`) selektivno je napadao određene Safe + signer adrese. Injected logic se izvršavao neposredno pre signing call-a:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Svojstva napada
- **Context-gated**: hard-coded allowlists za victim Safe-ove/signere sprečile su šum i smanjile mogućnost detekcije.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) bila su prepisana neposredno pre poziva `signTransaction`, a zatim vraćena, tako da su proposal payload-i u UI-ju izgledali bezopasno, dok su potpisi odgovarali attacker payload-u.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallet-i su prikazivali strukturirane podatke, ali nisu dekodirali ugnježđeni calldata niti isticali `operation = delegatecall`, zbog čega je mutirana poruka praktično bila blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevantnost validacije Gateway-a
Safe proposals se šalju na **Safe Client Gateway**.<sup>[[5]](#references)</sup> Pre uvođenja hardened provera, gateway je mogao da prihvati proposal u kojem su `safeTxHash`/signature odgovarali drugačijim poljima od onih u JSON body-ju, ako bi ih UI prepisao nakon potpisivanja. Nakon incidenta, gateway sada odbija proposals čiji hash/signature ne odgovaraju poslatoj transakciji.<sup>[[3]](#references)</sup> Sličnu server-side proveru hash-a treba primeniti na svaki signing-orchestration API.

### Najvažnije činjenice incidenta Bybit/Safe iz 2025.
- Pražnjenje Bybit cold-walleta 21. februara 2025. (~401k ETH) koristilo je isti obrazac: kompromitovani Safe S3 bundle aktivirao se samo za Bybit signere i zamenio `operation=0` → `1`, usmeravajući `to` na unapred deploy-ovan attacker contract koji upisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` prikazuje logiku vezanu za Bybit-ov Safe (`0x1db9…cf4`) i adrese signera, nakon čega je, dva minuta posle izvršavanja, odmah vraćena na čist bundle, što oponaša trik „mutate → sign → restore“.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (npr. `0x9622…c7242`) sadržao je jednostavne funkcije `sweepETH/sweepERC20` i `transfer(address,uint256)` koja upisuje implementation slot. Izvršavanje `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` promenilo je proxy implementation i omogućilo potpunu kontrolu.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover putem kolizije slotova

Safe proxies čuvaju `masterCopy` u **storage slot 0** i delegiraju svu logiku na njega. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka potpisana transakcija može da uputi poziv proizvoljnom contract-u i izvrši njegov kod u storage kontekstu proxy-ja.<sup>[[3]](#references)</sup>

Attacker contract je oponašao ERC-20 `transfer(address,uint256)`, ali je umesto toga upisivao `_to` u slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Putanja izvršavanja:<sup>[[1]](#references)[[3]](#references)</sup>
1. Žrtve potpisuju `execTransaction` sa `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validira potpise nad ovim parametrima.
3. Proxy izvršava delegatecall u `attackerContract`; telo funkcije `transfer` upisuje slot 0.
4. Slot 0 (`masterCopy`) sada pokazuje na logiku pod kontrolom napadača → **potpuno preuzimanje walleta i pražnjenje sredstava**.

### Napomene o guard-u i verziji (hardening nakon incidenta)
- Transaction guard-ovi uvedeni su u Safe v1.3.0 i mogu da pregledaju sve `execTransaction` parametre pre izvršavanja; guard može da odbije `delegatecall` ili da primeni policy nad odredištem i calldata-om. Bybit je koristio v1.1.1, koji je prethodio ovom hook-u.<sup>[[2]](#references)[[6]](#references)</sup>

## Kontrolna lista za detekciju i hardening

- **Integritet UI-ja**: pin-ujte JS asset-e / SRI; pratite razlike između bundle-ova; tretirajte signing UI kao deo granice poverenja.
- **Validacija u trenutku potpisivanja**: hardware wallet-i sa **EIP-712 clear-signing** funkcijom; eksplicitno prikažite `operation` i dekodirajte ugnježdeni calldata. Odbijte potpisivanje kada je `operation = 1`, osim ako policy to dozvoljava.<sup>[[3]](#references)</sup>
- **Provere hash-a na strani servera**: gateway-i/servisi koji prosleđuju proposals moraju ponovo da izračunaju `safeTxHash` i potvrde da se potpisi podudaraju sa poslatim poljima.<sup>[[3]](#references)</sup>
- **Policy/allowlist-e**: preflight pravila za `to`, selektore i tipove asset-a, uz zabranu delegatecall-a osim u proverеним flow-ovima. Zahtevajte interni policy servis pre broadcast-ovanja potpuno potpisanih transakcija.
- **Dizajn contract-a**: izbegavajte izlaganje proizvoljnog delegatecall-a u multisig/treasury wallet-ima osim kada je strogo neophodno. Svaki implementation pointer tretirajte kao upgrade primitiv: zaštitite ga eksplicitnom kontrolom pristupa i guard-ujte delegatecall target-e/selektore; samo premeštanje pointer-a u drugi slot nije potpuna odbrana.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: generišite upozorenja za delegatecall izvršavanja iz wallet-a koji drže treasury sredstva, kao i za proposals koji menjaju `operation` iz uobičajenih `call` obrazaca.

## References

- [1] [Forenzička analiza Bybit Safe exploita kompanije AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitovanja Safe bundle-a kompanije Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaljna tehnička analiza Bybit hack-a (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
