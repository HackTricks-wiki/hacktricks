# Kompromitacja procesu podpisywania Web3 i przejęcie proxy przez Safe Delegatecall

## Przegląd

Łańcuch kradzieży środków z cold-walleta połączył **supply-chain compromise interfejsu webowego Safe{Wallet}** z **on-chain primitive delegatecall, który nadpisał wskaźnik implementacji proxy (slot 0)**. Najważniejsze wnioski:

- Jeśli dApp może wstrzyknąć kod do ścieżki podpisywania, może sprawić, że signer wygeneruje prawidłowy **podpis EIP-712 dla pól wybranych przez attackera**, jednocześnie przywracając oryginalne dane interfejsu, aby pozostali signerzy nie zdawali sobie z tego sprawy.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies przechowują `masterCopy` (implementation) w **storage slot 0**. Delegatecall do kontraktu, który zapisuje dane w slocie 0, skutecznie „upgraduję” Safe do logiki attackera, zapewniając mu pełną kontrolę nad walletem.<sup>[[3]](#references)</sup>

## Off-chain: Ukierunkowana mutacja podpisywania w Safe{Wallet}

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
- **Context-gated**: hard-coded allowlists dla docelowych Safe'ów/signerów zapobiegały szumowi i obniżały wykrywalność.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane bezpośrednio przed `signTransaction`, a następnie przywracane, dzięki czemu payloady propozycji w UI wyglądały niewinnie, podczas gdy signatures odpowiadały payloadowi atakującego.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets wyświetlały dane strukturalne, ale nie dekodowały zagnieżdżonego calldata ani nie wyróżniały `operation = delegatecall`, przez co zmodyfikowana wiadomość była w praktyce blind-signed.<sup>[[3]](#references)[[4]](#references)</sup>

### Znaczenie walidacji Gateway
Propozycje Safe są przesyłane do **Safe Client Gateway**.<sup>[[5]](#references)</sup> Przed wdrożeniem zaostrzonych kontroli gateway mógł zaakceptować propozycję, w której `safeTxHash`/signature odpowiadały innym polom niż te w JSON body, jeśli UI przepisywał je po podpisaniu. Po incydencie gateway odrzuca propozycje, których hash/signature nie odpowiadają przesłanej transakcji.<sup>[[3]](#references)</sup> Podobną server-side hash verification należy wymuszać w każdym signing-orchestration API.

### Najważniejsze informacje o incydencie Bybit/Safe z 2025 roku
- Opróżnienie cold walleta Bybit z 21 lutego 2025 roku (~401 tys. ETH) wykorzystywało ten sam pattern: zaatakowany Safe S3 bundle uruchamiał się wyłącznie dla signerów Bybit i zamieniał `operation=0` → `1`, wskazując `to` na wcześniej wdrożony attacker contract, który zapisywał slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Zbuforowany przez Wayback `_app-52c9031bfa03da47.js` pokazuje logikę opartą na Safe Bybit (`0x1db9…cf4`) i adresach signerów, po czym natychmiast przywracano clean bundle dwie minuty po wykonaniu, odtwarzając trik „mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (np. `0x9622…c7242`) zawierał proste funkcje `sweepETH/sweepERC20` oraz `transfer(address,uint256)`, która zapisywała implementation slot. Wykonanie `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` zmieniało implementation proxy i zapewniało pełną kontrolę.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover przez kolizję slotów

Safe proxies przechowują `masterCopy` w **storage slot 0** i delegują całą logikę do tego adresu. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda signed transaction może wskazywać dowolny contract i wykonywać jego kod w kontekście storage proxy.<sup>[[3]](#references)</sup>

Attacker contract naśladował ERC-20 `transfer(address,uint256)`, ale zamiast tego zapisywał `_to` w slocie 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
3. Proxy wykonuje delegatecall do `attackerContract`; ciało `transfer` zapisuje slot 0.
4. Slot 0 (`masterCopy`) wskazuje teraz na logikę kontrolowaną przez attackera → **pełne przejęcie walleta i drenaż środków**.

### Uwagi dotyczące Guard i wersji (hardening po incydencie)
- Transaction guards wprowadzono w Safe v1.3.0; mogą sprawdzać wszystkie parametry `execTransaction` przed wykonaniem. Guard może odrzucić `delegatecall` albo wymusić politykę dotyczącą celu i calldata. Bybit korzystał z v1.1.1, która poprzedzała ten hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Lista kontrolna wykrywania i hardeningu

- **Integralność UI**: przypinaj assety JS / SRI; monitoruj różnice między bundle'ami; traktuj UI podpisywania jako część granicy zaufania.
- **Walidacja w momencie podpisywania**: hardware wallets z **EIP-712 clear-signing**; jawnie wyświetlaj `operation` i dekoduj zagnieżdżony calldata. Odrzucaj podpis, gdy `operation = 1`, chyba że zezwala na to polityka.<sup>[[3]](#references)</sup>
- **Weryfikacja hashy po stronie serwera**: gatewaye/serwisy przekazujące propozycje muszą ponownie obliczać `safeTxHash` i sprawdzać, czy podpisy odpowiadają przesłanym polom.<sup>[[3]](#references)</sup>
- **Polityki/allowlisty**: reguły preflight dla `to`, selectorów i typów assetów oraz blokowanie delegatecall z wyjątkiem zweryfikowanych przepływów. Przed broadcastem w pełni podpisanych transakcji wymagaj użycia wewnętrznego serwisu polityk.
- **Projekt kontraktu**: unikaj udostępniania arbitralnego delegatecall w walletach multisig/treasury, chyba że jest to absolutnie konieczne. Traktuj każdy pointer implementacji jako prymityw upgrade'u: chroń go za pomocą jawnej kontroli dostępu oraz zabezpieczaj cele/selektory delegatecall; samo przeniesienie pointera do innego slota nie jest kompletną obroną.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: generuj alerty dotyczące wykonań delegatecall z walletów przechowujących środki treasury oraz propozycji zmieniających `operation` względem typowych wzorców `call`.

## References

- [1] [Analiza kryminalistyczna exploita Safe w Bybit autorstwa AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitacji bundla Safe autorstwa Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Szczegółowa analiza techniczna hacku Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
