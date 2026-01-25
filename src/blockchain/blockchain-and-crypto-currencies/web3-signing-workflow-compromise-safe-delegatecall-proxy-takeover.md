# Naruszenie procesu podpisywania Web3 i przejęcie proxy Safe przez delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Łańcuch kradzieży cold-wallet połączył **supply-chain compromise of the Safe{Wallet} web UI** z **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Kluczowe wnioski:

- Jeśli dApp może wstrzyknąć kod w ścieżkę podpisywania, może zmusić podpisującego do wygenerowania prawidłowego **EIP-712 signature over attacker-chosen fields** jednocześnie przywracając oryginalne dane UI, tak że pozostali podpisujący niczego nie zauważą.
- Safe proxies przechowują `masterCopy` (implementation) w **storage slot 0**. Wywołanie delegatecall do kontraktu, który zapisuje do slot 0, skutecznie „aktualizuje” Safe do logiki atakującego, dając pełną kontrolę nad portfelem.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Sfałszowany pakiet Safe (`_app-*.js`) selektywnie atakował konkretne adresy Safe + signerów. Wstrzyknięta logika wykonywała się tuż przed wywołaniem podpisu:
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
### Właściwości ataku
- **Context-gated**: hard-coded allowlists dla ofiar Safe/podpisujących zapobiegały szumowi i obniżały wykrywalność.
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane tuż przed `signTransaction`, a następnie przywracane, więc payloady propozycji w UI wyglądały na nieszkodliwe, podczas gdy podpisy odpowiadały ładunkowi atakującego.
- **EIP-712 opacity**: portfele pokazywały dane strukturalne, ale nie dekodowały zagnieżdżonego calldata ani nie wyróżniały `operation = delegatecall`, przez co zmodyfikowana wiadomość była faktycznie podpisywana „na ślepo”.

### Gateway validation relevance
Safe proposals są przesyłane do **Safe Client Gateway**. Przed zaostrzeniem kontroli gateway mógł zaakceptować propozycję, w której `safeTxHash`/signature odpowiadały innym polom niż ciało JSON, jeśli UI przepisywało je po podpisaniu. Po incydencie gateway odrzuca propozycje, których hash/signature nie zgadzają się z przesłaną transakcją. Podobna weryfikacja hash po stronie serwera powinna być wymuszona na każdym API orkiestrującym podpisywanie.

### 2025 Bybit/Safe incident highlights
- 21 lutego 2025 wyciek środków z cold-wallet Bybit (~401k ETH) ponownie zastosował ten sam wzorzec: skompromitowany Safe S3 bundle uruchamiał się tylko dla podpisujących Bybit i zamieniał `operation=0` → `1`, kierując `to` na wcześniej wdrożony kontrakt atakującego, który zapisywał slot 0.
- Wayback-cached `_app-52c9031bfa03da47.js` pokazuje logikę opartą na Safe Bybit (`0x1db9…cf4`) i adresach podpisujących, po czym natychmiast przywrócono czysty bundle dwie minuty po wykonaniu, odzwierciedlając sztuczkę „mutate → sign → restore”.
- Złośliwy kontrakt (np. `0x9622…c7242`) zawierał proste funkcje `sweepETH/sweepERC20` oraz `transfer(address,uint256)`, który zapisywał slot implementacji. Wykonanie `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` zmieniło implementację proxy i zapewniło pełną kontrolę.

## On-chain: Delegatecall proxy takeover via slot collision

Proxies Safe przechowują `masterCopy` w **storage slot 0** i delegują do niego całą logikę. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda podpisana transakcja może wskazać dowolny kontrakt i wykonać jego kod w kontekście storage proxy.

Złośliwy kontrakt podszywał się pod ERC-20 `transfer(address,uint256)`, ale zamiast tego zapisywał `_to` w slocie 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy validates signatures over these parameters.
3. Proxy delegatecalls into `attackerContract`; the `transfer` body writes slot 0.
4. Slot 0 (`masterCopy`) now points to attacker-controlled logic → **pełne przejęcie portfela i wypływ środków**.

### Guard & version notes (post-incident hardening)
- Safes >= v1.3.0 can install a **Guard** to veto `delegatecall` or enforce ACLs on `to`/selectors; Bybit ran v1.1.1, so no Guard hook existed. Upgrading contracts (and re-adding owners) is required to gain this control plane.

## Detection & hardening checklist

- **Integralność UI**: pin JS assets / SRI; monitor bundle diffs; treat signing UI as part of the trust boundary.
- **Weryfikacja w czasie podpisu**: portfele sprzętowe z **EIP-712 clear-signing**; jawnie renderuj `operation` i zdekoduj zagnieżdżone calldata. Odrzuć podpisywanie gdy `operation = 1`, chyba że polityka na to pozwala.
- **Server-side hash checks**: gateways/services that relay proposals must recompute `safeTxHash` and validate signatures match the submitted fields.
- **Polityka / listy dozwolonych (allowlists)**: reguły preflight dla `to`, selektorów, typów aktywów i zablokuj delegatecall poza zatwierdzonymi przepływami. Wymagaj wewnętrznego serwisu polityk przed broadcastem w pełni podpisanych transakcji.
- **Contract design**: unikaj wystawiania dowolnego delegatecall w multisig/treasury wallets, chyba że jest to absolutnie konieczne. Umieść wskaźniki upgrade z dala od slotu 0 lub zabezpiecz je explicite logiką upgrade i kontrolą dostępu.
- **Monitoring**: alertuj o wykonaniach delegatecall z portfeli trzymających środki skarbca oraz o propozycjach, które zmieniają `operation` z typowych wzorców `call`.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
