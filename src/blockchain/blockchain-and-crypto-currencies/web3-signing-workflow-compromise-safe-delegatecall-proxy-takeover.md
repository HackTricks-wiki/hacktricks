# Kompromitovanje Web3 signing workflow-a i preuzimanje Safe delegatecall proxy-ja

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Lanac krađe cold wallet-a kombinovao je **supply-chain compromise Safe{Wallet} web UI-ja** sa **on-chain delegatecall primitive-om koji je prepisao implementation pointer proxy-ja (slot 0)**. Ključni zaključci su:

- Ako dApp može da ubaci kod u signing path, može navesti signer-a da proizvede validan **EIP-712 signature nad poljima koja je izabrao attacker**<sup>[[4]](#references)</sup> dok istovremeno vraća originalne UI podatke, tako da drugi signer-i ostanu nesvesni.
- Safe proxy-ji čuvaju `masterCopy` (implementation) u **storage slot-u 0**. Delegatecall ka contract-u koji upisuje u slot 0 efektivno „upgrade-uje“ Safe na attacker logic, čime se dobija potpuna kontrola nad wallet-om.

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
- **Context-gated**: hard-coded allowlists za victimske Safe-ove/signers sprečavale su šum i smanjivale detekciju.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) bila su prepisana neposredno pre `signTransaction`, a zatim vraćena, tako da su payload-i predloga u UI-ju izgledali bezazleno, dok su potpisi odgovarali attacker payload-u.
- **EIP-712 opacity**: wallet-i su prikazivali strukturirane podatke, ali nisu dekodirali ugnježdeni calldata niti isticali `operation = delegatecall`, zbog čega je mutirana poruka praktično bila blind-signed.

### Relevantnost Gateway validacije
Safe predlozi se šalju na **Safe Client Gateway**.<sup>[[5]](#references)</sup> Pre uvođenja hardened provera, gateway je mogao da prihvati predlog u kojem su `safeTxHash`/signature odgovarali drugačijim poljima nego što su navedena u JSON telu, ako ih je UI prepisao nakon potpisivanja. Nakon incidenta, gateway sada odbija predloge čiji hash/signature ne odgovaraju prosleđenoj transakciji. Sličnu server-side proveru hash-a treba primeniti na svaki signing-orchestration API.

### Istaknute činjenice incidenta Bybit/Safe iz 2025.
- Pražnjenje Bybit cold-wallet-a 21. februara 2025. (~401k ETH) koristilo je isti obrazac: kompromitovani Safe S3 bundle aktivirao se samo za Bybit signers i zamenio `operation=0` → `1`, usmeravajući `to` na unapred deploy-ovan attacker contract koji upisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` prikazuje logiku vezanu za Bybit-ov Safe (`0x1db9…cf4`) i signer adrese, nakon čega je bundle odmah vraćen na čistu verziju, dva minuta nakon izvršenja, što preslikava trik „mutate → sign → restore“.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (npr. `0x9622…c7242`) sadržao je jednostavne funkcije `sweepETH/sweepERC20` i `transfer(address,uint256)` koja upisuje implementation slot. Izvršavanje `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` promenilo je proxy implementation i omogućilo potpunu kontrolu.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Preuzimanje proxy-ja putem Delegatecall-a zbog kolizije slotova

Safe proxy-ji čuvaju `masterCopy` u **storage slot-u 0** i delegiraju svu logiku na njega. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka potpisana transakcija može da usmeri poziv na proizvoljan contract i izvrši njegov kod u storage kontekstu proxy-ja.<sup>[[3]](#references)</sup>

Attacker contract je imitirao ERC-20 `transfer(address,uint256)`, ali je umesto toga upisivao `_to` u slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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

### Napomene o Guard-u i verziji (ojačavanje nakon incidenta)
- Safes >= v1.3.0 mogu instalirati **Guard** za odbijanje `delegatecall`-a ili primenu ACL-ova na `to`/selektore; Bybit je koristio v1.1.1, tako da hook za Guard nije postojao. Neophodno je nadograditi contracts (i ponovo dodati owners) da bi se dobila ova kontrolna ravan.

## Kontrolna lista za detekciju i ojačavanje

- **Integritet UI-ja**: fiksirajte JS assets / SRI; nadgledajte razlike između bundle-ova; tretirajte signing UI kao deo granice poverenja.
- **Validacija u trenutku potpisivanja**: hardware wallets sa **EIP-712 clear-signing**; eksplicitno prikažite `operation` i dekodirajte ugnježđeni calldata. Odbijte potpisivanje kada je `operation = 1`, osim ako policy to dozvoljava.
- **Provere hash-a na serverskoj strani**: gateways/services koji prosleđuju proposals moraju ponovo izračunati `safeTxHash` i proveriti da potpisi odgovaraju poslatim poljima.
- **Policy/allowlists**: preflight rules za `to`, selektore i tipove assets, uz zabranu delegatecall-a osim u proverеним flows. Zahtevajte interni policy service pre broadcast-ovanja potpuno potpisanih transactions.
- **Dizajn contract-a**: izbegavajte izlaganje proizvoljnom delegatecall-u u multisig/treasury wallets, osim ako je strogo neophodno. Postavite upgrade pointers dalje od slot-a 0 ili ih zaštitite eksplicitnom upgrade logikom i access control-om.
- **Monitoring**: generišite alerts za delegatecall executions iz walleta koji drže treasury sredstva, kao i za proposals koji menjaju `operation` u odnosu na uobičajene `call` obrasce.

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
