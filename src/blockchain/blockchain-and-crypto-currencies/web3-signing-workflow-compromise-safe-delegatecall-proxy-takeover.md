# Kompromitovanje Web3 toka potpisivanja i preuzimanje Safe Delegatecall Proxy-ja

## Pregled

Lanac krađe iz cold wallet-a kombinovao je **supply-chain compromise Safe{Wallet} web UI-ja** sa **on-chain delegatecall primitivom koji je prepisao pokazivač na implementaciju proxy-ja (slot 0)**. Ključni zaključci su:

- Ako dApp može da ubaci code u putanju potpisivanja, može navesti signera da generiše važeći **EIP-712 potpis nad poljima koja je izabrao attacker**, a zatim obnoviti originalne UI podatke tako da ostali signeri ne primete promenu.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies čuvaju `masterCopy` (implementaciju) u **storage slot 0**. Delegatecall ka contractu koji upisuje u slot 0 efektivno „upgrade-uje“ Safe na attacker logiku, čime se dobija potpuna kontrola nad wallet-om.<sup>[[3]](#references)</sup>

## Off-chain: Ciljana mutacija potpisivanja u Safe{Wallet}-u

Izmenjeni Safe bundle (`_app-*.js`) selektivno je napadao određene Safe + signer adrese. Injected logika se izvršavala neposredno pre signing poziva:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists za victim Safe-ove/signere sprečile su šum i smanjile detekciju.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) bila su prepisana neposredno pre `signTransaction`, a zatim vraćena, tako da su payload-i predloga u UI-ju izgledali benigno, dok su potpisi odgovarali payload-u napadača.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallet-i su prikazivali strukturirane podatke, ali nisu dekodirali ugnježdeni calldata niti isticali `operation = delegatecall`, zbog čega je izmenjena poruka praktično bila blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Relevantnost Gateway validacije
Safe predlozi se šalju na **Safe Client Gateway**.<sup>[[5]](#references)</sup> Pre uvođenja ojačanih provera, gateway je mogao da prihvati predlog kod kojeg su `safeTxHash`/potpis odgovarali drugačijim poljima od onih u JSON telu, ako ih je UI prepisao nakon potpisivanja. Nakon incidenta, gateway sada odbija predloge čiji hash/potpis ne odgovara poslatoj transakciji.<sup>[[3]](#references)</sup> Sličnu server-side verifikaciju hash-a treba sprovoditi na svakom API-ju za orkestraciju potpisivanja.

### Istaknute činjenice incidenta Bybit/Safe iz 2025.
- Pražnjenje Bybit cold wallet-a od 21. februara 2025. (~401k ETH) koristilo je isti obrazac: kompromitovani Safe S3 bundle aktivirao se samo za Bybit signere i zamenio `operation=0` sa `1`, usmeravajući `to` na unapred deploy-ovan ugovor napadača koji upisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-keširani `_app-52c9031bfa03da47.js` prikazuje logiku vezanu za Bybit-ov Safe (`0x1db9…cf4`) i adrese signera, nakon čega je bundle odmah vraćen na čistu verziju dva minuta nakon izvršenja, što odražava trik „mutate → sign → restore“.<sup>[[1]](#references)[[2]](#references)</sup>
- Zlonamerni ugovor (npr. `0x9622…c7242`) sadržao je jednostavne funkcije `sweepETH/sweepERC20` i `transfer(address,uint256)` koja upisuje implementation slot. Izvršavanje `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` promenilo je implementaciju proxy-ja i dalo potpunu kontrolu.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Preuzimanje proxy-ja putem Delegatecall-a izazvanog kolizijom slotova

Safe proxy-ji čuvaju `masterCopy` u **storage slotu 0** i delegiraju svu logiku na njega. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka potpisana transakcija može da uputi na proizvoljan ugovor i izvrši njegov kod u storage kontekstu proxy-ja.<sup>[[3]](#references)</sup>

Ugovor napadača oponašao je ERC-20 `transfer(address,uint256)`, ali je umesto toga upisivao `_to` u slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
4. Slot 0 (`masterCopy`) sada pokazuje na logiku pod kontrolom napadača → **potpuno preuzimanje walleta i izvlačenje sredstava**.

### Beleške o guard-u i verziji (ojačavanje nakon incidenta)
- Transaction guards su uvedeni u Safe v1.3.0 i mogu da provere sve `execTransaction` parametre pre izvršavanja; guard može da odbije `delegatecall` ili da primeni pravila nad odredištem i calldata-om. Bybit je koristio v1.1.1, koji prethodi ovom hook-u.<sup>[[2]](#references)[[6]](#references)</sup>

## Kontrolna lista za detekciju i ojačavanje

- **Integritet UI-ja**: pinujte JS assete / SRI; pratite razlike između bundle-ova; tretirajte signing UI kao deo granice poverenja.
- **Validacija u trenutku potpisivanja**: hardware wallets sa **EIP-712 clear-signing** podrškom; eksplicitno prikažite `operation` i dekodirajte ugnježdeni calldata. Odbijte potpisivanje kada je `operation = 1`, osim ako pravila to dozvoljavaju.<sup>[[3]](#references)</sup>
- **Provere hash-a na serverskoj strani**: gateway-i/servisi koji prosleđuju predloge moraju ponovo izračunati `safeTxHash` i proveriti da potpisi odgovaraju poslatim poljima.<sup>[[3]](#references)</sup>
- **Pravila/allowlists**: preflight pravila za `to`, selektore i tipove asseta, uz zabranu delegatecall-a osim za proverene tokove. Zahtevajte interni policy servis pre broadcast-a potpuno potpisanih transakcija.
- **Dizajn contracta**: izbegavajte izlaganje proizvoljnog delegatecall-a u multisig/treasury walletima, osim kada je to strogo neophodno. Svaki pokazivač na implementaciju tretirajte kao upgrade primitive: zaštitite ga eksplicitnom kontrolom pristupa i guard-om za delegatecall odredišta/selektore; samo premeštanje pokazivača u drugi slot nije potpuna zaštita.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: generišite upozorenja za delegatecall izvršavanja iz walleta koji drže treasury sredstva, kao i za predloge koji menjaju `operation` u odnosu na uobičajene `call` obrasce.

## References

- [1] [Forenzička analiza Bybit Safe exploita kompanije AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitovanja Safe bundle-a kompanije Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaljna tehnička analiza Bybit hacka (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Dnevnik izmena za Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
