# Bezbednosne zamke ERC-4337 pametnih naloga

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 apstrakcija naloga pretvara novčanike u programabilne sisteme. Osnovni tok je **validate-then-execute** kroz ceo bundle: `EntryPoint` validira svaki `UserOperation` pre nego što izvrši bilo koji od njih. Ovakav redosled stvara ne-očiglednu napadnu površinu kada je validacija permisivna, ima stanje ili nije usklađena sa pravilima simulacije bundlera.

## 1) Zaobilaženje direktnim pozivom privilegovanih funkcija
Svaka eksterno poziva dostupna funkcija `execute` (ili funkcija za premeštanje sredstava) koja nije ograničena na `EntryPoint` (ili provereni executor modul) može biti direktno pozvana radi pražnjenja naloga.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezbedan obrazac: ograničite na `EntryPoint`, a koristite `msg.sender == address(this)` za tokove administracije/samoupravljanja (instaliranje modula, promene validatora, nadogradnje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili neproverena gas polja -> iscrpljivanje naknada
Ako validacija potpisa obuhvata samo nameru (`callData`), ali ne i polja povezana sa gasom, bundler ili frontrunner može da uveća naknade i iscrpi ETH. Potpisani payload mora da obuhvati najmanje:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Odbrambeni obrazac: koristite `userOpHash` koji obezbeđuje `EntryPoint` (a koji uključuje gas polja) i/ili strogo ograničite svako polje.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering stateful validation (semantika bundle-a)
Pošto se sve validacije izvršavaju pre bilo kakvog izvršavanja, čuvanje rezultata validacije u stanju contract-a nije bezbedno. Druga op u istom bundle-u može da ga prepiše, zbog čega će vaše izvršavanje koristiti stanje pod kontrolom attacker-a.<sup>[[1]](#references)</sup>

Izbegavajte upisivanje u storage u `validateUserOp`. Ako je neizbežno, privremene podatke indeksirajte pomoću `userOpHash` i deterministički ih obrišite nakon upotrebe (prednost dajte stateless validaciji).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay između account-a i chain-ova (nedostaje domain separation)
`isValidSignature(bytes32 hash, bytes sig)` mora da veže signature za **ovaj contract** i **ovaj chain**. Verifikacija nad raw hash-om omogućava replay između account-a ili chain-ova.<sup>[[1]](#references)</sup>

Koristite EIP-712 typed data (domain uključuje `verifyingContract` i `chainId`) i pri uspehu vratite tačnu ERC-1271 magic vrednost `0x1626ba7e`.<sup>[[1]](#references)</sup>

## 5) Revert-i ne vraćaju sredstva nakon validacije
Kada `validateUserOp` uspe, fee-jevi su već rezervisani čak i ako execution kasnije izazove revert. Attacker-i mogu neprekidno da šalju op-ove koji će neuspešno izvršiti operaciju, a da i dalje naplaćuju fee-jeve sa account-a.<sup>[[1]](#references)</sup>

Kod paymaster-a, plaćanje iz shared pool-a u `validateUserOp` i naplaćivanje korisnicima u `postOp` je nepouzdano, jer `postOp` može da izazove revert bez poništavanja plaćanja. Zaštitite sredstva tokom validacije (escrow/deposit po korisniku), učinite `postOp` minimalnim i takvim da ne izaziva revert, i predvidite `paymasterPostOpGasLimit` za najgori mogući reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / pretpostavke o factory-ju
Prvi `UserOperation` često sadrži `initCode`, što uzrokuje da se account deploy-uje preko **factory-ja** tokom validacije. Ovaj path se lako nedovoljno audit-uje, jer se izvršava samo pri prvoj upotrebi.<sup>[[2]](#references)</sup>

Uobičajeni propusti:

- Factory/initializer veruje uslovu `msg.sender == entryPoint`, ali ERC-4337 deployment path **ne poziva** `initCode` direktno iz `EntryPoint`-a.
- Salt, owner, validator ili konfiguracija module-a nisu u potpunosti vezani za potpisanu nameru, pa frontrunner može da pretekne prvo deploy-ovanje i zauzme counterfactual address podešavanjima pod kontrolom attacker-a.
- Factory nije idempotent-an, pa ponovljeni first-use flow blokira wallet umesto da vrati već kreiranu address-u.

Bezbedan pattern: ponovo izračunajte očekivani sender na osnovu potpisanih deployment parametara, učinite deployment determinističkim (obično pomoću `CREATE2`) i omogućite initialization samo jednom.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Validation logika koju bundleri odbacuju
Validation kod može biti ispravan u lokalnim testovima, a ipak neupotrebljiv u realnim bundlerima. Javni bundleri simuliraju `validateUserOp()` / `validatePaymasterUserOp()` off-chain i često pokreću potpunu `debug_traceCall(handleOps)` proveru pre uključivanja.

Zbog toga su ovi obrasci opasni unutar validation-a:

- Opcode-i zavisni od bloka, kao što su `TIMESTAMP`, `NUMBER` ili `BLOCKHASH`
- Upisivanja stanja, kao što je `SSTORE`
- Neograničeno iteriranje kroz storage
- Proizvoljni eksterni pozivi ili čitanja iz oracle-a koja se mogu promeniti između simulacije i uključivanja

Loš primer:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // SSTORE in validation
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Tretirajte validaciju kao determinističku, ograničenu preflight funkciju. Ako su vam zaista potrebni deljeno stanje ili spoljašnje provere, prebacite tu složenost u staked entitete čija se reputacija prati i testirajte tačnu putanju bundler simulacije, a ne samo unit testove.

## 8) ERC-7702 frontrun inicijalizacije
ERC-7702 omogućava EOA-u da izvršava smart-account kod tokom jednog tx-a. Ako je inicijalizacija dostupna eksterno, frontrunner može sebe postaviti kao vlasnika.<sup>[[1]](#references)</sup>

Mitigacija: dozvolite inicijalizaciju samo putem **self-call-a** i samo jednom.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Brze provere pre merge-a
- Validirajte potpise koristeći `EntryPoint`-ov `userOpHash` (povezuje gas polja).
- Ograničite privilegovane funkcije na `EntryPoint` i/ili `address(this)`, prema potrebi.
- Neka `validateUserOp` bude bez stanja, deterministički i kompatibilan sa pravilima bundler simulacije.
- Primenite EIP-712 razdvajanje domena za ERC-1271 i pri uspehu vratite `0x1626ba7e`.
- Neka `postOp` bude minimalan, ograničen i bez mogućnosti reverzije; obezbedite naknade tokom validacije.
- Testirajte prvu `initCode` putanju zasebno: determinističko deployment-ovanje, idempotentno ponašanje factory-ja i jednokratnu inicijalizaciju.
- Pre isporuke pokrenite kompletnu bundler simulaciju (`simulateValidation` plus praćeni `handleOps`).
- Za ERC-7702 dozvolite init samo tokom self-call-a i samo jednom.



## Reference

- [1] [Šest grešaka u ERC-4337 smart account-ima (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Apstrakcija naloga korišćenjem Alt Mempool-a](https://eips.ethereum.org/EIPS/eip-4337)

{{#include ../../banners/hacktricks-training.md}}
