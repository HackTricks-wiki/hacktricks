# Przejęcie procesu podpisywania Web3 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Łańcuch kradzieży cold-wallet łączył kompromis łańcucha dostaw interfejsu webowego Safe{Wallet} z prymitywem on-chain delegatecall, który nadpisał wskaźnik implementacji proxy (slot 0). Kluczowe wnioski są następujące:

- Jeśli dApp może wstrzyknąć kod w ścieżkę podpisywania, może sprawić, że signer wygeneruje prawidłowy **EIP-712 signature over attacker-chosen fields**, a jednocześnie przywrócić oryginalne dane UI, tak że inni signerzy pozostaną nieświadomi.
- Safe proxies przechowują `masterCopy` (implementation) w **storage slot 0**. Wywołanie delegatecall do kontraktu, który zapisuje do slotu 0, efektywnie „aktualizuje” Safe do logiki atakującego, dając pełną kontrolę nad walletem.

## Off-chain: Ukierunkowana mutacja podpisu w Safe{Wallet}

Zmodyfikowany bundle Safe (`_app-*.js`) selektywnie atakował konkretne adresy Safe i signerów. Wstrzyknięta logika wykonywała się tuż przed wywołaniem podpisu:
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
- **Context-gated**: twardo zakodowane allowlisty dla Safes i sygnatariuszy zapobiegały generowaniu szumu i zmniejszały wykrywalność.
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane bezpośrednio przed `signTransaction`, a następnie przywracane, więc treści propozycji w UI wyglądały nieszkodliwie, podczas gdy podpisy odpowiadały payloadowi atakującego.
- **EIP-712 opacity**: portfele wyświetlały dane strukturalne, ale nie dekodowały zagnieżdżonego calldata ani nie podkreślały `operation = delegatecall`, przez co zmieniona wiadomość była podpisywana praktycznie na ślepo.

### Znaczenie walidacji bramy
Propozycje Safe są przesyłane do **Safe Client Gateway**. Przed zaostrzeniem kontroli bramka mogła zaakceptować propozycję, w której `safeTxHash`/podpis odpowiadał innym polom niż ciało JSON, jeśli UI przepisało je po podpisaniu. Po incydencie bramka odrzuca propozycje, których hash/podpis nie zgadzają się z przesłaną transakcją. Podobna weryfikacja hashu po stronie serwera powinna być wymuszana dla każdego API orkiestrującego podpisy.

## On-chain: Przejęcie proxy przez delegatecall w wyniku kolizji slotów

Proksy Safe przechowują `masterCopy` w **storage slot 0** i delegują do niego całą logikę. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda podpisana transakcja może wskazać dowolny kontrakt i wykonać jego kod w kontekście storage proksy.

Złośliwy kontrakt imitował ERC-20 `transfer(address,uint256)`, ale zamiast tego zapisał `_to` do slotu 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ścieżka wykonania:
1. Victims sign `execTransaction` with `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy weryfikuje podpisy dla tych parametrów.
3. Proxy wykonuje delegatecall do `attackerContract`; ciało `transfer` zapisuje slot 0.
4. Slot 0 (`masterCopy`) teraz wskazuje na logikę kontrolowaną przez atakującego → **pełne przejęcie portfela i wyprowadzenie środków**.

## Lista kontrolna wykrywania i utwardzania

- **Integralność UI**: przypnij zasoby JS / SRI; monitoruj różnice w bundle; traktuj interfejs podpisywania jako część granicy zaufania.
- **Walidacja w czasie podpisu**: portfele sprzętowe z **EIP-712 clear-signing**; jawnie renderuj `operation` i dekoduj zagnieżdżone calldata. Odrzuć podpisywanie gdy `operation = 1`, chyba że polityka na to pozwala.
- **Sprawdzanie hashy po stronie serwera**: bramki/usługi przekazujące propozycje muszą przeliczyć `safeTxHash` i zweryfikować, że podpisy odpowiadają przesłanym polom.
- **Polityki/allowlists**: reguły preflight dla `to`, selektorów, typów aktywów i zabroń delegatecall poza sprawdzonymi ścieżkami. Wymagaj wewnętrznej usługi polityki przed rozgłaszaniem w pełni podpisanych transakcji.
- **Projekt kontraktu**: unikaj eksponowania dowolnego delegatecall w multisig/treasury wallets, chyba że jest to absolutnie konieczne. Umieszczaj wskaźniki upgrade z dala od slot 0 lub zabezpieczaj je eksplicytną logiką upgrade i kontrolą dostępu.
- **Monitorowanie**: generuj alerty przy wykonaniach delegatecall z portfeli przechowujących środki skarbca oraz przy propozycjach zmieniających `operation` z typowych wzorców `call`.

## Źródła

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
