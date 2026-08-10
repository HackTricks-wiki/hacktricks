# Bezbednosni propusti ERC-4337 Smart Account-a

ERC-4337 account abstraction pretvara novčanike u programabilne sisteme. Osnovni tok je **validate-then-execute** kroz ceo bundle: `EntryPoint` validira svaki `UserOperation` pre izvršavanja bilo kog od njih.<sup>[[5]](#references)</sup> Ovakav redosled stvara neočiglednu attack surface kada je validacija previše permisivna, stateful ili neusaglašena sa pravilima bundler simulation-a.

## 1) Zaobilaženje privilegovanih funkcija direktnim pozivom
Svaka eksterno dostupna funkcija `execute` (ili funkcija za premeštanje sredstava) koja nije ograničena na `EntryPoint` (ili provereni executor module) može biti direktno pozvana radi pražnjenja naloga.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezbedan obrazac: ograničite na `EntryPoint` i koristite `msg.sender == address(this)` za tokove administracije/samoupravljanja (instaliranje modula, promene validatora, nadogradnje).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili neproverena gas polja -> iscrpljivanje naknada
Ako validacija potpisa pokriva samo nameru (`callData`), ali ne i polja povezana sa gasom, bundler ili frontrunner može da uveća naknade i isprazni ETH. Potpisani payload mora da obuhvati najmanje:<sup>[[2]](#references)</sup>

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Defensive pattern: koristite `userOpHash` koji obezbeđuje `EntryPoint` (a koji uključuje gas polja) i/ili strogo ograničite svako polje.<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(_isApprovedCall(userOpHash, op.signature), "bad sig");
return 0;
}
```
## 3) Clobbering stateful validation (semantika paketa)
Pošto se sve validacije izvršavaju pre bilo kakvog izvršenja, čuvanje rezultata validacije u stanju ugovora nije bezbedno. Druga op u istom paketu može da ih prepiše, zbog čega vaše izvršenje može da koristi stanje pod uticajem napadača.<sup>[[2]](#references)</sup>

Izbegavajte upisivanje u storage u `validateUserOp`. Ako je neizbežno, privremene podatke vezujte za `userOpHash` i deterministički ih obrišite nakon upotrebe (prednost dajte stateless validaciji).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay između naloga/lanaca (nedostaje domain separation)
`isValidSignature(bytes32 hash, bytes sig)` mora da veže potpise za **ovaj ugovor** i **ovaj lanac**. Oporavak nad sirovim hash-om omogućava replay između naloga ili lanaca.<sup>[[1]](#references)[[4]](#references)</sup>

Koristite EIP-712 typed data (domain uključuje `verifyingContract` i `chainId`) i pri uspehu vratite tačnu ERC-1271 magic value `0x1626ba7e`.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert-i ne vraćaju sredstva nakon validacije
Kada `validateUserOp` uspe, naknade su obavezane čak i ako izvršenje kasnije doživi revert. Napadači mogu iznova da šalju op-e koji će neuspešno završiti, a da i dalje naplaćuju naknade sa naloga.<sup>[[2]](#references)</sup>

Kod paymaster-a, plaćanje iz zajedničkog pool-a u `validateUserOp` i naplaćivanje korisnicima u `postOp` predstavlja slab obrazac, jer `postOp` može da doživi revert bez poništavanja plaćanja. Obezbedite sredstva tokom validacije (escrow/deposit po korisniku), učinite `postOp` minimalnim i takvim da ne može da doživi revert, i predvidite `paymasterPostOpGasLimit` za putanju refundacije u najgorem slučaju.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / pretpostavke factory-ja
Prva `UserOperation` često sadrži `initCode`, zbog čega se nalog deploy-uje putem **factory-ja** tokom validacije. Ovaj put je lako nedovoljno audit-ovati jer se izvršava samo pri prvoj upotrebi.<sup>[[5]](#references)</sup>

Uobičajeni propusti uključuju:<sup>[[5]](#references)</sup>

- Factory/initializer veruje uslovu `msg.sender == entryPoint`, ali ERC-4337 deployment putanja ne poziva `initCode` direktno iz `EntryPoint`-a.
- Salt, vlasnik, validator ili konfiguracija modula nisu u potpunosti vezani za potpisanu nameru, pa frontrunner može da pretekne prvu deployment operaciju i zauzme counterfactual adresu podešavanjima pod kontrolom napadača.
- Factory nije idempotentan, pa ponovljena putanja pri prvoj upotrebi blokira wallet umesto da vrati već kreiranu adresu.

Bezbedan obrazac: ponovo izračunajte očekivanog sender-a na osnovu potpisanih deployment parametara, učinite deployment determinističkim (obično pomoću `CREATE2`) i omogućite inicijalizaciju samo jednom.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika validacije koju bundleri odbacuju
Kod za validaciju može biti ispravan u lokalnim testovima, a ipak neupotrebljiv u stvarnim bundlerima. Bundleri pokreću validaciju više puta i trebalo bi da izvrše potpunu validaciju celog bundle-a uz tracing pre slanja.<sup>[[6]](#references)</sup>

Prema tim pravilima opsega validacije, sledeći obrasci su opasni:<sup>[[6]](#references)</sup>

- Opkodi zavisni od bloka, kao što su `TIMESTAMP`, `NUMBER` ili `BLOCKHASH`
- Pristup storage-u izvan dozvoljenog opsega account-a/entity-ja ili neograničena iteracija kroz storage
- External calls ili čitanja oracle-a koja zavise od promenljivog stanja izvan dozvoljenog opsega validacije

Loš primer:
```solidity
function validateUserOp(UserOperation calldata op, bytes32 userOpHash, uint256)
external
returns (uint256)
{
require(block.timestamp < expiry, "expired");
seen[userOpHash] = true; // stateful validation can be clobbered by another op
require(oracle.isAllowed(op.sender), "oracle changed");
return 0;
}
```
Tretirajte validaciju kao determinističku, ograničenu preflight funkciju. Ako su neophodni deljeno stanje ili eksterna pretraživanja, pratite pravila za staked entitete i testirajte isti multi-pass bundler simulacioni put, a ne samo unit testove.<sup>[[6]](#references)</sup>

## 8) ERC-7702 front-run inicijalizacije
ERC-7702 daje EOA trajnu delegaciju ka smart-account kodu; delegacija ne izvršava inicijalizaciju atomski. Ako je inicijalizacija eksterno poziva, posmatrač može da izvrši front-run i postavi sebe za vlasnika.<sup>[[7]](#references)</sup>

Mitigacija: zahtevajte da initialization calldata bude autorizovan od strane EOA i omogućite inicijalizaciju samo jednom. U ERC-4337 EIP-7702 toku, takođe ograničite pozivaoca na `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Brze provere pre spajanja
- Validirajte potpise koristeći `EntryPoint`-ov `userOpHash` (povezuje gas polja).
- Ograničite privilegovane funkcije na `EntryPoint` i/ili `address(this)`, prema potrebi.
- Održavajte `validateUserOp` bez stanja, determinističkim i kompatibilnim sa pravilima simulacije bundler-a.
- Primenite razdvajanje domena EIP-712 za ERC-1271 i pri uspehu vratite `0x1626ba7e`.
- Održavajte `postOp` minimalnim, ograničenim i bez mogućnosti reversion-a; obezbedite naknade tokom validacije.
- Testirajte prvu `initCode` putanju zasebno: determinističku deployment, idempotentno ponašanje factory-ja i jednokratnu inicijalizaciju.
- Pokrenite bundler-ovu višestruku validaciju i proveru celog bundle-a sa trace-om pre objavljivanja.
- Za ERC-7702 povežite init sa EOA autorizacijom i dozvolite ga samo jednom; u ERC-4337 tokovima ograničite pozivaoca na `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - Pogođeno više od 15 timova (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Šest grešaka u ERC-4337 smart account-ima (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardni metod validacije potpisa za contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hashing i potpisivanje tipiziranih strukturiranih podataka](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction korišćenjem Alt Mempool-a](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Pravila opsega validacije za Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Postavljanje koda za EOA-ove](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
