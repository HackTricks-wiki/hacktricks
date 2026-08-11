# Bezbednosni propusti ERC-4337 pametnih naloga

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 apstrakcija naloga pretvara novčanike u programabilne sisteme. Osnovni tok je **validate-then-execute** kroz ceo bundle: `EntryPoint` validira svaki `UserOperation` pre izvršavanja bilo kog od njih.<sup>[[5]](#references)</sup> Ovakav redosled stvara ne-očiglednu attack surface kada je validacija permisivna, stateful ili neusaglašena sa pravilima bundler simulacije.

## 1) Zaobilaženje privilegovanih funkcija direktnim pozivom
Svaka eksterno pozivaiva funkcija `execute` (ili funkcija koja premešta sredstva) koja nije ograničena na `EntryPoint` (ili provereni executor module) može biti direktno pozvana radi pražnjenja naloga.<sup>[[2]](#references)</sup>
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezbedan obrazac: ograničite na `EntryPoint` i koristite `msg.sender == address(this)` za tokove administracije/samoupravljanja (instalacija modula, promene validatora, nadogradnje).<sup>[[2]](#references)[[5]](#references)</sup>
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili neproverena gas polja -> pražnjenje naknada
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
## 3) Prepisivanje stateful validacije (semantika bundle-a)
Pošto se sve validacije izvršavaju pre bilo kakvog izvršavanja, čuvanje rezultata validacije u stanju contract-a nije bezbedno. Drugi op u istom bundle-u može da ih prepiše, zbog čega vaše izvršavanje može da koristi state pod kontrolom attackera.<sup>[[2]](#references)</sup>

Izbegavajte upisivanje u storage u `validateUserOp`. Ako je to neizbežno, privremene podatke vezujte za `userOpHash` i deterministički ih obrišite nakon upotrebe (prednost dajte stateless validaciji).<sup>[[2]](#references)</sup>

## 4) ERC-1271 replay između naloga/chain-ova (nedostaje domain separation)
`isValidSignature(bytes32 hash, bytes sig)` mora da veže potpise za **ovaj contract** i **ovaj chain**. Recovering nad raw hash-om omogućava replay između naloga ili chain-ova.<sup>[[1]](#references)[[4]](#references)</sup>

Koristite EIP-712 typed data (domain uključuje `verifyingContract` i `chainId`) i pri uspehu vratite tačnu ERC-1271 magic vrednost `0x1626ba7e`.<sup>[[3]](#references)[[4]](#references)</sup>

## 5) Revert-i ne vraćaju sredstva nakon validacije
Kada `validateUserOp` uspe, naknade su već rezervisane, čak i ako izvršavanje kasnije doživi revert. Attackeri mogu iznova da šalju op-ove koji će neuspešno završiti, a da i dalje naplaćuju naknade sa naloga.<sup>[[2]](#references)</sup>

Kod paymaster-a, plaćanje iz shared pool-a u `validateUserOp` i naplaćivanje korisnicima u `postOp` predstavlja krhko rešenje, jer `postOp` može da doživi revert bez poništavanja plaćanja. Obezbedite sredstva tokom validacije (per-user escrow/deposit), držite `postOp` minimalnim i bez mogućnosti revert-a i predvidite `paymasterPostOpGasLimit` za najgori slučaj reimbursement putanje.<sup>[[2]](#references)[[5]](#references)</sup>

## 6) Counterfactual deployment / pretpostavke o factory-ju
Prvi `UserOperation` često sadrži `initCode`, što uzrokuje da se account deploy-uje kroz **factory** tokom validacije. Ovaj path se lako nedovoljno audit-uje jer se izvršava samo pri prvom korišćenju.<sup>[[5]](#references)</sup>

Uobičajeni propusti uključuju:<sup>[[5]](#references)</sup>

- Factory/initializer veruje uslovu `msg.sender == entryPoint`, ali ERC-4337 deployment path **ne poziva** `initCode` direktno iz `EntryPoint`.
- Salt, owner, validator ili konfiguracija module-a nisu u potpunosti vezani za potpisanu nameru, pa frontrunner može da pretekne prvi deployment i zauzme counterfactual adresu sa attacker-kontrolisanim podešavanjima.
- Factory nije idempotentan, pa ponovljeni first-use flow onesposobi wallet umesto da vrati već kreiranu adresu.

Bezbedan obrazac: ponovo izračunajte očekivanog sender-a na osnovu potpisanih deployment parametara, učinite deployment determinističkim (obično pomoću `CREATE2`) i omogućite initialization samo jednom.<sup>[[5]](#references)</sup>
```solidity
bytes32 salt = keccak256(abi.encode(owner, validator, saltNonce));
address predicted = Create2.computeAddress(salt, keccak256(initCode));
require(predicted == sender, "bad sender");
```
## 7) Logika validacije koju bundleri odbacuju
Kod za validaciju može biti ispravan u lokalnim testovima, a ipak neupotrebljiv u stvarnim bundlerima. Bundleri pokreću validaciju više puta i trebalo bi da izvrše potpunu validaciju celog bundle-a uz tracing pre slanja.<sup>[[6]](#references)</sup>

Prema tim pravilima opsega validacije, sledeći obrasci su opasni:<sup>[[6]](#references)</sup>

- Opcode-i zavisni od bloka, kao što su `TIMESTAMP`, `NUMBER` ili `BLOCKHASH`
- Pristup storage-u izvan dozvoljenog opsega account-a/entity-ja ili neograničena iteracija kroz storage
- External calls ili čitanja iz oracle-a koja zavise od promenljivog state-a izvan dozvoljenog opsega validacije

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
Tretirajte validaciju kao determinističku, ograničenu preflight funkciju. Ako su neophodni deljeno stanje ili eksterni upiti, pratite pravila za staked entitete i testirajte isti multi-pass bundler simulation path, a ne samo unit testove.<sup>[[6]](#references)</sup>

## 8) ERC-7702 initialization frontrun
ERC-7702 daje EOA trajnu delegaciju na smart-account code; delegacija ne pokreće initialization atomski. Ako je initialization javno pozivljiv, posmatrač može da izvrši front-run i postavi sebe za vlasnika.<sup>[[7]](#references)</sup>

Mitigacija: zahtevajte da initialization calldata bude autorizovan od strane EOA i dozvolite initialization samo jednom. U ERC-4337 EIP-7702 toku takođe ograničite pozivaoca na `EntryPoint.senderCreator()`.<sup>[[5]](#references)[[7]](#references)</sup>
```solidity
function initialize(address newOwner, bytes calldata initSig) external {
require(owner == address(0), "already inited");
// Verify the EOA's signature over the complete initialization calldata.
require(_isAuthorizedByEOA(newOwner, initSig), "bad init auth");
owner = newOwner;
}
```
## Brze provere pre spajanja
- Validirajte potpise koristeći `userOpHash` iz `EntryPoint`-a (vezuje gas polja).
- Ograničite privilegovane funkcije na `EntryPoint` i/ili `address(this)`, prema potrebi.
- Održavajte `validateUserOp` bez stanja, determinističkim i kompatibilnim sa pravilima simulacije bundler-a.
- Primenite EIP-712 razdvajanje domena za ERC-1271 i pri uspehu vratite `0x1626ba7e`.
- Održavajte `postOp` minimalnim, ograničenim i bez mogućnosti revert-a; obezbedite naknade tokom validacije.
- Testirajte prvu `initCode` putanju zasebno: determinističko deployment-ovanje, idempotentno ponašanje factory-ja i jednokratnu inicijalizaciju.
- Pre isporuke pokrenite multi-pass validaciju bundler-a i proveru celog bundle-a sa trace-om.
- Za ERC-7702 povežite init sa autorizacijom EOA-a i dozvolite ga samo jednom; u ERC-4337 tokovima ograničite pozivaoca na `EntryPoint.senderCreator()`.

## References

- [1] [Replay ERC1271 - pogođeno više od 15 timova (curiousapple)](https://paragraph.com/@curiousapple/fwlBuaAuGsWwLRPTLKxB)
- [2] [Šest grešaka u ERC-4337 smart account-ima (Trail of Bits)](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)
- [3] [ERC-1271: Standardni metod validacije potpisa za contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [4] [EIP-712: Hash-ovanje i potpisivanje tipiziranih strukturiranih podataka](https://eips.ethereum.org/EIPS/eip-712)
- [5] [ERC-4337: Account Abstraction korišćenjem Alt Mempool-a](https://eips.ethereum.org/EIPS/eip-4337)
- [6] [ERC-7562: Pravila opsega validacije za Account Abstraction](https://eips.ethereum.org/EIPS/eip-7562)
- [7] [EIP-7702: Postavljanje koda za EOA-e](https://eips.ethereum.org/EIPS/eip-7702)
{{#include ../../banners/hacktricks-training.md}}
