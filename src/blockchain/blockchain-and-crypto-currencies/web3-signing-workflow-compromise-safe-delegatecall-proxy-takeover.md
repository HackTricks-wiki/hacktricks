# Kompromitovanje Web3 procesa potpisivanja i preuzimanje Safe Delegatecall Proxy-ja

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Lanac krađe sa cold wallet-a kombinovao je **supply-chain compromise web UI-ja Safe{Wallet}** sa **on-chain delegatecall primitivom koji je prepisao pokazivač na implementaciju proxy-ja (slot 0)**. Ključni zaključci su:

- Ako dApp može da ubaci code u proces potpisivanja, može navesti signer-a da generiše važeći **EIP-712 potpis nad poljima koja je izabrao attacker**, a zatim vratiti originalne UI podatke kako drugi signer-i ne bi ništa primetili.
- Safe proxy-ji čuvaju `masterCopy` (implementaciju) u **storage slot-u 0**. Delegatecall ka contract-u koji upisuje u slot 0 efektivno „upgrade-uje“ Safe na attacker logiku, čime se dobija potpuna kontrola nad wallet-om.

## Van lanca: Ciljana mutacija potpisivanja u Safe{Wallet}-u

Izmenjeni Safe bundle (`_app-*.js`) selektivno je napadao određene Safe + signer adrese. Injected logic se izvršavao neposredno pre poziva za potpisivanje:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists za victimske Safe-ove/signere sprečavale su noise i smanjivale detekciju.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) bila su prepisana neposredno pre `signTransaction`, a zatim vraćena, tako da su proposal payloads u UI-ju izgledali benigno, dok su signatures odgovarali attacker payload-u.
- **EIP-712 opacity**: wallets su prikazivali strukturirane podatke, ali nisu dekodirali nested calldata niti isticali `operation = delegatecall`, zbog čega je mutated message praktično bio blind-signed.

### Relevantnost Gateway validation-a
Safe proposals se šalju na **Safe Client Gateway**. Pre uvođenja hardened checks, gateway je mogao da prihvati proposal u kojem su `safeTxHash`/signature odgovarali drugačijim fields od onih u JSON body-ju ako ih je UI prepisao nakon signing-a. Nakon incidenta, gateway sada odbija proposals čiji hash/signature ne odgovaraju submitted transaction-u. Slična server-side hash verification treba da bude obavezna na svakom signing-orchestration API-ju.

### Istaknuti detalji Bybit/Safe incidenta iz 2025.
- Pražnjenje Bybit cold wallet-a 21. februara 2025. (~401k ETH) koristilo je isti pattern: kompromitovani Safe S3 bundle aktivirao se samo za Bybit signers i zamenio `operation=0` → `1`, usmeravajući `to` na pre-deployed attacker contract koji upisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Wayback-cached `_app-52c9031bfa03da47.js` prikazuje da je logika bila vezana za Bybit-ov Safe (`0x1db9…cf4`) i signer addresses, a zatim je odmah vraćena na clean bundle dva minuta nakon izvršenja, što oponaša trik „mutate → sign → restore“.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (npr. `0x9622…c7242`) sadržao je jednostavne functions `sweepETH/sweepERC20` i `transfer(address,uint256)` koji upisuje implementation slot. Izvršavanje `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` promenilo je proxy implementation i omogućilo potpunu kontrolu.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover putem slot collision-a

Safe proxies čuvaju `masterCopy` u **storage slot 0** i svu logiku prosleđuju na njega. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka signed transaction može da uputi poziv ka proizvoljnom contract-u i izvrši njegov code u storage context-u proxy-ja.<sup>[[3]](#references)</sup>

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

### Beleške o Guard-u i verziji (ojačavanje nakon incidenta)
- Safes >= v1.3.0 mogu instalirati **Guard** za blokiranje `delegatecall` ili primenu ACL-ova na `to`/selektore; Bybit je koristio v1.1.1, tako da nije postojao Guard hook. Neophodno je nadograditi contracts (i ponovo dodati owners) da bi se dobila ova kontrolna ravan.

## Kontrolna lista za detekciju i ojačavanje

- **Integritet UI-ja**: fiksirati JS assets / SRI; pratiti razlike između bundle-ova; tretirati signing UI kao deo granice poverenja.
- **Validacija u trenutku potpisivanja**: hardware wallets sa **EIP-712 clear-signing**; eksplicitno prikazati `operation` i dekodirati ugnježdeni calldata. Odbiti potpisivanje kada je `operation = 1`, osim ako policy to dozvoljava.
- **Provere hash-eva na strani servera**: gateways/services koji prosleđuju proposals moraju ponovo izračunati `safeTxHash` i proveriti da potpisi odgovaraju poslatim poljima.
- **Policy/allowlists**: preflight rules za `to`, selektore, tipove asseta i zabranu delegatecall-a, osim kod proverenih tokova. Zahtevati interni policy service pre broadcast-a potpuno potpisanih transakcija.
- **Dizajn contracta**: izbegavati izlaganje proizvoljnom delegatecall-u u multisig/treasury walletima, osim ako je strogo neophodno. Postaviti upgrade pointers izvan slota 0 ili ih zaštititi eksplicitnom upgrade logikom i access control-om.
- **Monitoring**: generisati upozorenja za delegatecall izvršavanja iz walleta koji drže treasury sredstva, kao i za proposals kod kojih se `operation` menja u odnosu na uobičajene `call` obrasce.

## Reference

- [1] [Forenzička analiza Bybit Safe exploita kompanije AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitovanja Safe bundle-a kompanije Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Detaljna tehnička analiza Bybit hack-a (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
