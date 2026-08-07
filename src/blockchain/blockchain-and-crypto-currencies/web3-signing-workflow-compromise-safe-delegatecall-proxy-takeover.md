# Kompromitacja procesu podpisywania Web3 i przejęcie proxy Safe za pomocą delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Łańcuch kradzieży z cold-wallet połączył **kompromitację łańcucha dostaw interfejsu webowego Safe{Wallet}** z **on-chain primitive delegatecall, która nadpisała wskaźnik implementacji proxy (slot 0)**. Najważniejsze wnioski:

- Jeśli dApp może wstrzyknąć kod do procesu podpisywania, może sprawić, że signer wygeneruje prawidłowy **podpis EIP-712 dla pól wybranych przez attackera**<sup>[[4]](#references)</sup>, jednocześnie przywracając oryginalne dane interfejsu, aby pozostali signerzy niczego nie zauważyli.
- Proxy Safe przechowują `masterCopy` (implementację) w **storage slot 0**. Delegatecall do kontraktu, który zapisuje dane w slocie 0, skutecznie „upgrade’uje” Safe do logiki attackera, zapewniając mu pełną kontrolę nad wallet.

## Off-chain: ukierunkowana modyfikacja podpisywania w Safe{Wallet}

Zmodyfikowany bundle Safe (`_app-*.js`) atakował selektywnie określone adresy Safe i signerów. Wstrzyknięta logika wykonywała się bezpośrednio przed wywołaniem podpisywania:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists dla docelowych Safe/signers zapobiegały szumowi i obniżały wykrywalność.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: pola (`to`, `data`, `operation`, gas) były nadpisywane bezpośrednio przed `signTransaction`, a następnie przywracane, dlatego payloady propozycji w UI wyglądały niewinnie, podczas gdy podpisy odpowiadały payloadowi atakującego.
- **EIP-712 opacity**: portfele wyświetlały dane strukturalne, ale nie dekodowały zagnieżdżonych calldata ani nie wyróżniały `operation = delegatecall`, przez co zmodyfikowana wiadomość była w praktyce podpisywana bez weryfikacji.

### Znaczenie walidacji Gateway
Propozycje Safe są przesyłane do **Safe Client Gateway**.<sup>[[5]](#references)</sup> Przed wprowadzeniem wzmocnionych kontroli Gateway mógł zaakceptować propozycję, w której `safeTxHash`/podpis odpowiadały innym polom niż te w body JSON, jeśli UI przepisał je po podpisaniu. Po incydencie Gateway odrzuca teraz propozycje, których hash/podpis nie odpowiada przesłanej transakcji. Podobna weryfikacja hashy po stronie serwera powinna być wymagana w każdym API do orkiestracji podpisywania.

### Najważniejsze informacje o incydencie Bybit/Safe z 2025 roku
- Drenaż cold walleta Bybit z 21 lutego 2025 roku (~401k ETH) wykorzystywał ten sam wzorzec: przejęty bundle Safe S3 uruchamiał się tylko dla signerów Bybit i zamieniał `operation=0` → `1`, wskazując `to` na wcześniej wdrożony kontrakt atakującego, który zapisuje slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Zbuforowany przez Wayback `_app-52c9031bfa03da47.js` pokazuje logikę opartą na Safe Bybit (`0x1db9…cf4`) i adresach signerów, po czym bundle został natychmiast przywrócony do czystej wersji dwie minuty po wykonaniu, co odwzorowuje sztuczkę „mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Złośliwy kontrakt (np. `0x9622…c7242`) zawierał proste funkcje `sweepETH/sweepERC20` oraz `transfer(address,uint256)`, która zapisuje slot implementacji. Wykonanie `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` zmieniło implementację proxy i zapewniło pełną kontrolę.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: przejęcie proxy przez Delegatecall wskutek kolizji slotów

Proxy Safe przechowują `masterCopy` w **storage slot 0** i delegują do niego całą logikę. Ponieważ Safe obsługuje **`operation = 1` (delegatecall)**, każda podpisana transakcja może wskazywać dowolny kontrakt i wykonywać jego kod w kontekście storage proxy.<sup>[[3]](#references)</sup>

Kontrakt atakującego naśladował `transfer(address,uint256)` ERC-20, ale zamiast tego zapisywał `_to` w slocie 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
4. Slot 0 (`masterCopy`) wskazuje teraz na logikę kontrolowaną przez atakującego → **pełne przejęcie walleta i opróżnienie środków**.

### Uwagi dotyczące Guard i wersji (hardening po incydencie)
- Safes >= v1.3.0 mogą zainstalować **Guard**, aby blokować `delegatecall` lub wymuszać ACL dla `to`/selectorów; Bybit używał v1.1.1, więc nie istniał hook Guard. Wymagana jest aktualizacja kontraktów (i ponowne dodanie ownerów), aby uzyskać tę control plane.

## Checklista wykrywania i hardeningu

- **Integralność UI**: przypinaj zasoby JS / SRI; monitoruj różnice między bundle’ami; traktuj signing UI jako część granicy zaufania.
- **Walidacja w momencie podpisywania**: hardware wallets z **EIP-712 clear-signing**; jawnie renderuj `operation` i dekoduj zagnieżdżone calldata. Odrzucaj podpisywanie, gdy `operation = 1`, chyba że polityka na to zezwala.
- **Sprawdzanie hashy po stronie serwera**: gatewaye/usługi przekazujące proposals muszą ponownie obliczać `safeTxHash` i sprawdzać, czy podpisy odpowiadają przesłanym polom.
- **Polityki/allowlisty**: reguły preflight dla `to`, selectorów i typów aktywów oraz blokowanie delegatecall poza zweryfikowanymi flow. Wymagaj wewnętrznego serwisu polityk przed broadcastowaniem w pełni podpisanych transakcji.
- **Projektowanie kontraktów**: unikaj udostępniania arbitralnego delegatecall w walletach multisig/treasury, chyba że jest to ściśle konieczne. Umieszczaj wskaźniki upgrade’ów z dala od slotu 0 lub zabezpieczaj je jawną logiką upgrade’u i kontrolą dostępu.
- **Monitoring**: generuj alerty dotyczące wykonań delegatecall z walletów przechowujących środki treasury oraz proposals, które zmieniają `operation` z typowych wzorców `call`.

## References

- [1] [Analiza kryminalistyczna exploita Bybit Safe autorstwa AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Analiza kompromitacji bundle’a Safe autorstwa Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Szczegółowa analiza techniczna hacku Bybit (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
