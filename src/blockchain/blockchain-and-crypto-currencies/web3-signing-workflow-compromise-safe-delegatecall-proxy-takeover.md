# Kupotoshwa kwa Web3 Signing Workflow & Kukamatwa kwa Proxy ya Safe kwa Delegatecall

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Mlolongo wa wizi wa cold-wallet uliunganisha **supply-chain compromise of the Safe{Wallet} web UI** na **on-chain delegatecall primitive that overwrote a proxy’s implementation pointer (slot 0)**. Mambo muhimu ya kujifunza ni:

- Ikiwa dApp inaweza kuingiza code katika njia ya kusaini, inaweza kumfanya signer atengeneze saini halali ya **EIP-712 signature over attacker-chosen fields** wakati ikirejesha data ya UI ya awali ili signers wengine waendelee kutojua.
- Safe proxies hifadhi `masterCopy` (implementation) katika **storage slot 0**. Delegatecall kwa mkataba unaoandika kwenye slot 0 kwa ufanisi “inaboresha” Safe kwa logic ya mshambuliaji, ikitoa udhibiti kamili wa wallet.

## Nje ya mnyororo: Ubadilishaji uliolengwa wa kusaini katika Safe{Wallet}

Bundle ya Safe iliyodanganywa (`_app-*.js`) ilishambulia kwa uteuzi anwani maalum za Safe + signer. Mantiki iliyochomwa ilitekelezwa tu kabla ya wito la kusaini:
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
### Sifa za shambulio
- **Context-gated**: allowlists zilizowekwa kwa hard-coded kwa Safe/signers wa wahanga ziliizuia kelele na kupunguza ugunduzi.
- **Last-moment mutation**: mashamba (`to`, `data`, `operation`, gas) yaliandikwa upya mara moja kabla ya `signTransaction`, kisha yarudi kama awali, hivyo payloads za mapendekezo kwenye UI zilionekana salama wakati saini zililingana na payload ya mshambuliaji.
- **EIP-712 opacity**: wallets zilionyesha data iliyopangwa lakini hazikutafsiri calldata ya ndani wala kuangazia `operation = delegatecall`, jambo lililofanya ujumbe uliobadilishwa kusainiwa bila kusomewa kwa undani.

### Umuhimu wa uthibitisho wa Gateway
Mapendekezo ya Safe yanwasilishwa kwenye **Safe Client Gateway**. Kabla ya ukaguzi kuwa mkali, gateway inaweza kukubali pendekezo ambapo `safeTxHash`/sahihi zililingana na mashamba tofauti kuliko mwili wa JSON ikiwa UI iliandika upya baada ya kusaini. Baada ya tukio, gateway sasa inakataa mapendekezo ambayo hash/sahihi hazilingani na muamala uliotumwa. Uthibitisho wa hash upande wa server unafanana unapaswa kutekelezwa kwenye API yoyote ya signing-orchestration.

### Mambo muhimu kuhusu tukio la Bybit/Safe 2025
- Mnamo Februari 21, 2025 uvujaji wa cold-wallet wa Bybit (~401k ETH) ulitumia muundo ule ule: Safe S3 bundle iliyojeruhiwa ilizingatiwa tu kwa signers wa Bybit na ilibadilisha `operation=0` → `1`, ikiwekea `to` kwa kontrakta ya mshambuliaji iliyowekwa kabla iliyoyandikisha slot 0.
- Wayback-cached `_app-52c9031bfa03da47.js` inaonyesha mantiki iliyotegemea Safe ya Bybit (`0x1db9…cf4`) na anwani za signers, kisha mara moja ikarudishwa kwenye bundle safi baada ya dakika mbili ya utekelezaji, ikifanana na mbinu ya “badilisha → saini → rejesha”.
- Kontrakta ya uharibifu (km, `0x9622…c7242`) ilikuwa na funguo rahisi `sweepETH/sweepERC20` pamoja na `transfer(address,uint256)` ambayo inaandika slot ya implementation. Utekelezaji wa `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ulibadilisha implementation ya proxy na kutoa udhibiti kamili.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies huweka `masterCopy` katika **storage slot 0** na kutoa mantiki yote kwake. Kwa sababu Safe inaunga mkono **`operation = 1` (delegatecall)**, muamala wowote uliosainiwa unaweza kuelekeza kwa kontrakta yoyote na kutekeleza msimbo wake katika muktadha wa storage wa proxy.

Kontrakta ya mshambuliaji ilifanya kama ERC-20 `transfer(address,uint256)` lakini badala yake iliandika `_to` katika slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Waathiriwa wanafanya saini `execTransaction` kwa `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` inathibitisha saini juu ya vigezo hivi.
3. Proxy inafanya delegatecall kwenye `attackerContract`; mwili wa `transfer` unaandika slot 0.
4. Slot 0 (`masterCopy`) sasa inaelekeza kwenye logic inayodhibitiwa na mshambulizi → **kuchukuliwa kabisa kwa pochi na kuondolewa kwa fedha**.

### Guard & version notes (kuimarisha usalama baada ya tukio)
- Safes >= v1.3.0 zinaweza kusakinisha **Guard** kuzipinga `delegatecall` au kutekeleza ACLs kwa `to`/selectors; Bybit ilikimbia v1.1.1, hivyo hakuna Guard hook iliyokuwepo. Kusasisha contracts (na kuwarudisha wamiliki) kunahitajika ili kupata mchakato huu wa udhibiti.

## Orodha ya uchunguzi na kuimarisha usalama

- **UI integrity**: weka JS assets kwa pin / SRI; fuatilia bundle diffs; chukulia signing UI kama sehemu ya mpaka wa uaminifu.
- **Sign-time validation**: hardware wallets zenye **EIP-712 clear-signing**; onyesha wazi `operation` na decode calldata iliyofungwa ndani. Kataa kusaini wakati `operation = 1` isipokuwa sera inaruhusu.
- **Server-side hash checks**: gateways/services zinazotuma mapendekezo lazima zitatekeleza upya `safeTxHash` na kuthibitisha kuwa saini zinaendana na mashamba yaliyowasilishwa.
- **Policy/allowlists**: sheria za preflight kwa `to`, selectors, aina za mali, na kataa `delegatecall` isipokuwa kwa mtiririko uliokaguliwa. Inahitaji huduma ya sera ya ndani kabla ya kutuma fully signed transactions.
- **Contract design**: epuka kufichua delegatecall bila mpangilio katika multisig/treasury wallets isipokuwa inahitajika kabisa. Weka upgrade pointers mbali na slot 0 au zingatia kwa mantiki ya upgrade wazi na access control.
- **Monitoring**: tuma tahadhari kuhusu utekelezaji wa delegatecall kutoka kwa wallets zinazoimiliki fedha za hazina, na kwa mapendekezo yanayobadilisha `operation` kutoka kwenye mifumo ya kawaida ya `call`.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
