# Bezbednosne zamke ERC-4337 Smart Account-a

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 apstrakcija naloga pretvara wallet-e u programabilne sisteme. Osnovni tok je **validate-then-execute** kroz ceo paket: `EntryPoint` validira svaku `UserOperation` pre izvršavanja bilo koje od njih. Ovakav redosled stvara neočiglednu attack surface kada je validacija permisivna, stateful ili neusaglašena sa pravilima bundler simulacije.

## 1) Bypass direktnim pozivom privilegovanih funkcija
Svaka eksterno pozivaća `execute` funkcija (ili funkcija za premeštanje sredstava) koja nije ograničena na `EntryPoint` (ili provereni executor modul) može biti direktno pozvana radi pražnjenja naloga.<sup>[[1]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezbedan obrazac: ograničite na `EntryPoint` i koristite `msg.sender == address(this)` za administratorske tokove/samoupravljanje (instaliranje modula, promene validatora, nadogradnje).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili neproverena gas polja -> pražnjenje sredstava kroz naknade
Ako validacija potpisa obuhvata samo nameru (`callData`), ali ne i polja povezana sa gasom, bundler ili frontrunner može da uveća naknade i isprazni ETH. Potpisani payload mora da obuhvati najmanje:<sup>[[1]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: koristite `userOpHash` koji obezbeđuje `EntryPoint` (koji uključuje gas polja) i/ili strogo ograničite svako polje.<sup>[[1]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Prepisivanje stanja validacije (semantika bundle-a)
Pošto se sve validacije izvršavaju pre bilo kakvog izvršavanja, čuvanje rezultata validacije u stanju contracta nije bezbedno. Druga op operacija u istom bundle-u može da ih prepiše, zbog čega će se izvršavanje osloniti na stanje pod kontrolom attackera.<sup>[[1]](#references)</sup>

Izbegavajte upisivanje u storage u funkciji `validateUserOp`. Ako je to neizbežno, privremene podatke indeksirajte pomoću `userOpHash` i deterministički ih obrišite nakon upotrebe (prednost dajte stateless validaciji).<sup>[[1]](#references)</sup>

## 4) ERC-1271 replay između accounta/chainova (nedostaje domain separation)
`isValidSignature(bytes32 hash, bytes sig)` mora da veže potpise za **ovaj contract** i **ovaj chain**. Oporavak potpisa nad raw hash-om omogućava replay između accounta ili chainova.<sup>[[1]](#references)</sup>

Koristite EIP-712 typed data (domain uključuje `verifyingContract` i `chainId`) i pri uspehu vratite tačnu ERC-1271 magic vrednost `0x1626ba7e`.<sup>[[1]](#references)</sup>

## 5) Revert-i ne vraćaju sredstva nakon validacije
Kada `validateUserOp` uspe, naknade su već obavezane čak i ako izvršavanje kasnije doživi revert. Attackeri mogu neprekidno da šalju op operacije koje će neuspešno završiti, a da i dalje naplaćuju naknade sa accounta.<sup>[[1]](#references)</sup>

Kod paymastera, plaćanje iz zajedničkog pool-a u funkciji `validateUserOp` i naplaćivanje korisnicima u funkciji `postOp` predstavlja fragilan pristup, jer `postOp` može da doživi revert bez poništavanja plaćanja. Obezbedite sredstva tokom validacije (escrow/deposit po korisniku), održavajte `postOp` minimalnim i bez mogućnosti re verta, i predvidite `paymasterPostOpGasLimit` za najgori mogući reimbursement path.<sup>[[1]](#references)</sup>

## 6) Counterfactual deployment / factory pretpostavke
Prva `UserOperation` često sadrži `initCode`, što uzrokuje da se account deploy-uje preko **factory-ja** tokom validacije. Ovaj path se lako nedovoljno audit-uje jer se izvršava samo pri prvom korišćenju.<sup>[[2]](#references)</sup>

Česti problemi:

- Factory/initializer veruje uslovu `msg.sender == entryPoint`, ali ERC-4337 deployment path **ne poziva** `initCode` direktno iz `EntryPoint`-a.
- Salt, owner, validator ili konfiguracija modula nisu u potpunosti vezani za potpisanu nameru, pa frontrunner može da se utrkuje za prvi deployment i zauzme counterfactual adresu podešavanjima pod kontrolom attackera.
- Factory nije idempotentan, pa ponovljeni first-use flow blokira wallet umesto da vrati već kreiranu adresu.

Bezbedan obrazac: ponovo izračunajte očekivanog sendera na osnovu potpisanih deployment parametara, učinite deployment determinističkim (tipično pomoću `CREATE2`) i omogućite initialization samo jednom.<sup>[[2]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika validacije koju bundleri odbacuju
Kod za validaciju može biti ispravan u lokalnim testovima, a ipak neupotrebljiv u stvarnim bundlerima. Javni bundleri simuliraju `validateUserOp()` / `validatePaymasterUserOp()` off-chain i obično pokreću kompletan `debug_traceCall(handleOps)` pre uključivanja.<sup>[[3]](#references)</sup>

Zbog toga su sledeći obrasci opasni unutar validacije:

- Opcode-i zavisni od bloka, kao što su `TIMESTAMP`, `NUMBER` ili `BLOCKHASH`
- Upisi u stanje, kao što je `SSTORE`
- Neograničeno iteriranje kroz storage
- Proizvoljni eksterni pozivi ili čitanja sa oracle-a čija se vrednost može promeniti između simulacije i uključivanja

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
Tretirajte validaciju kao determinističku, ograničenu preflight funkciju. Ako vam je zaista potrebno deljeno stanje ili spoljne provere, prebacite tu složenost u entitete sa stakingom/ praćenom reputacijom i testirajte tačnu putanju simulacije bundlera, a ne samo unit testove.

## 8) ERC-7702 initialization frontrun
ERC-7702 omogućava EOA-u da izvršava smart-account kod tokom jedne tx. Ako je initialization javno pozivljiv, frontrunner može sebe postaviti za vlasnika.<sup>[[1]](#references)</sup>

Mitigacija: dozvolite initialization samo putem **self-call** poziva i samo jednom.<sup>[[1]](#references)</sup>
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Brze provere pre spajanja
- Validirajte potpise koristeći `EntryPoint`-ov `userOpHash` (vezuje gas polja).
- Ograničite privilegovane funkcije na `EntryPoint` i/ili `address(this)`, prema potrebi.
- Održavajte `validateUserOp` bez stanja, determinističkim i kompatibilnim sa pravilima bundler simulacije.
- Primenite EIP-712 razdvajanje domena za ERC-1271 i pri uspehu vratite `0x1626ba7e`.
- Održavajte `postOp` minimalnim, ograničenim i bez mogućnosti revert-a; obezbedite naknade tokom validacije.
- Testirajte prvu `initCode` putanju zasebno: determinističku deployment, idempotentno ponašanje factory-ja i jednokratnu inicijalizaciju.
- Pokrenite punu bundler simulaciju (`simulateValidation` plus praćeni `handleOps`) pre puštanja.
- Za ERC-7702, dozvolite init samo tokom self-call-a i samo jednom.

## Reference

- [1] [Šest grešaka u ERC-4337 smart account-ima (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [2] [ERC-4337: Apstrakcija naloga pomoću alternativnog Mempool-a](https://eips.ethereum.org/EIPS/eip-4337)
- [3] [ERC-7562: Pravila opsega validacije apstrakcije naloga](https://eips.ethereum.org/EIPS/eip-7562)

{{#include ../../banners/hacktricks-training.md}}
