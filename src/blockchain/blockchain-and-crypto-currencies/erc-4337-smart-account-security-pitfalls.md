# ERC-4337 pametni nalozi — bezbednosne zamke

{{#include ../../banners/hacktricks-training.md}}

ERC-4337 apstrakcija naloga pretvara novčanike u programabilne sisteme. Osnovni tok je **validate-then-execute** preko čitavog paketa: `EntryPoint` validira svaku `UserOperation` pre nego što izvrši bilo koju od njih. Ovaj redosled stvara nejasno vidljivu površinu napada kada je validacija permisivna ili zavisi od stanja.

## 1) Direktni poziv koji zaobilazi privilegovane funkcije
Bilo koja funkcija `execute` (ili funkcija za premeštanje sredstava) koja je dostupna za pozivanje spolja, a nije ograničena na `EntryPoint` (ili na proveren izvršni modul), može biti pozvana direktno i isprazniti nalog.
```solidity
function execute(address target, uint256 value, bytes calldata data) external {
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
Bezbedan obrazac: ograničiti na `EntryPoint`, i koristiti `msg.sender == address(this)` za admin/self-management tokove (module install, validator changes, upgrades).
```solidity
address public immutable entryPoint;

function execute(address target, uint256 value, bytes calldata data) external {
require(msg.sender == entryPoint, "not entryPoint");
(bool ok,) = target.call{value: value}(data);
require(ok, "exec failed");
}
```
## 2) Nepotpisana ili nekontrolisana polja vezana za gas -> pražnjenje ETH kroz naknade
Ako validacija potpisa pokriva samo nameru (`callData`), ali ne i polja vezana za gas, bundler ili frontrunner mogu napumpati naknade i isprazniti ETH. Potpisani payload mora da obuhvati barem:

- `preVerificationGas`
- `verificationGasLimit`
- `callGasLimit`
- `maxFeePerGas`
- `maxPriorityFeePerGas`

Odbrambeni obrazac: koristi `EntryPoint`-provided `userOpHash` (koji uključuje polja vezana za gas) i/ili strogo ograniči svako polje.
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
Pošto se sve validacije izvršavaju pre same eksekucije, čuvanje rezultata validacije u stanju ugovora nije bezbedno. Druga op u istom bundle-u može to prebrisati, što može dovesti do toga da se za izvršenje koristi stanje pod uticajem napadača.

Izbegavajte upis u storage unutar `validateUserOp`. Ako je neizbežno, indeksirajte privremene podatke po `userOpHash` i obrišite ih deterministički nakon upotrebe (poželjno je stateless validacija).

## 4) ERC-1271 replay između naloga/lanaca (nedostatak odvajanja domena)
`isValidSignature(bytes32 hash, bytes sig)` mora vezati potpise za **ovaj ugovor** i **ovu mrežu**. Rekoverovanje iz sirovog hash-a omogućava da se potpisi ponovo iskoriste između naloga ili lanaca.

Koristite EIP-712 typed data (domen uključuje `verifyingContract` i `chainId`) i vratite tačnu ERC-1271 magic vrednost `0x1626ba7e` pri uspehu.

## 5) Revertovi ne vraćaju sredstva nakon validacije
Kada `validateUserOp` uspe, naknade su obavezane čak i ako izvršenje kasnije revertuje. Napadači mogu ponavljano slati op-ove koji će propasti, a ipak naplaćivati naknade sa naloga.

Za paymaster-e, plaćanje iz zajedničkog pool-a u `validateUserOp` i naplata korisnicima u `postOp` je krhka zato što `postOp` može revertovati bez poništavanja plaćanja. Osigurajte sredstva tokom validacije (po-korisnički escrow/depozit) i držite `postOp` minimalnim i tako da ne revertuje.

## 6) ERC-7702 inicijalizacija frontrun
ERC-7702 omogućava EOA da pokrene smart-account kod za jednu tx. Ako je inicijalizacija pozvana spolja, frontrunner može sebe postaviti za vlasnika.

Mitigacija: dozvolite inicijalizaciju samo na **self-call** i samo jednom.
```solidity
function initialize(address newOwner) external {
require(msg.sender == address(this), "init: only self");
require(owner == address(0), "already inited");
owner = newOwner;
}
```
## Brze provere pre-merge-a
- Validirajte potpise koristeći `EntryPoint`-ov `userOpHash` (veže gas polja).
- Ograničite privilegovane funkcije na `EntryPoint` i/ili `address(this)` gde je prikladno.
- Održavajte `validateUserOp` bez stanja.
- Obezbedite EIP-712 razdvajanje domena za ERC-1271 i vratite `0x1626ba7e` pri uspehu.
- Održavajte `postOp` minimalnim, ograničenim i takvim da ne revertuje; obezbedite naknade tokom validacije.
- Za ERC-7702, dozvolite init samo pri self-call i samo jednom.

## Reference

- [https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/](https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/)

{{#include ../../banners/hacktricks-training.md}}
