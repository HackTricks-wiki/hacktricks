# Compromise ya Web3 Signing Workflow & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Msururu wa wizi wa cold-wallet uliunganisha **supply-chain compromise ya Safe{Wallet} web UI** na **on-chain delegatecall primitive iliyoandika upya implementation pointer ya proxy (slot 0)**. Mambo muhimu ya kuzingatia ni:

- Ikiwa dApp inaweza kuingiza code kwenye signing path, inaweza kumfanya signer atoe **EIP-712 signature halali yenye fields zilizochaguliwa na attacker**, huku ikirejesha data ya awali ya UI ili signers wengine wasitambue.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies huhifadhi `masterCopy` (implementation) kwenye **storage slot 0**. Delegatecall kwenye contract inayoandika kwenye slot 0 kimsingi “hu-upgrade” Safe kutumia attacker logic, na hivyo kumpa attacker udhibiti kamili wa wallet.<sup>[[3]](#references)</sup>

## Off-chain: Targeted signing mutation katika Safe{Wallet}

Safe bundle iliyochezewa (`_app-*.js`) ilishambulia kwa kuchagua Safe + signer addresses mahususi. Logic iliyodungwa ilitekelezwa mara moja kabla ya signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Sifa za attack
- **Context-gated**: allowlists zilizowekwa moja kwa moja kwa Safes/signers wa victims zilizuia noise na kupunguza detection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) zilibadilishwa mara moja kabla ya `signTransaction`, kisha zikarejeshwa, hivyo proposal payloads kwenye UI zilionekana kuwa salama huku signatures zikilingana na attacker payload.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets zilionyesha structured data lakini hazikufasiri nested calldata wala kuonyesha wazi `operation = delegatecall`, hivyo message iliyobadilishwa ilisainiwa bila kuonekana kwa undani.<sup>[[3]](#references)[[4]](#references)</sup>

### Umuhimu wa Gateway validation
Safe proposals huwasilishwa kwa **Safe Client Gateway**.<sup>[[5]](#references)</sup> Kabla ya hardened checks, gateway ingeweza kukubali proposal ambayo `safeTxHash`/signature yake ilihusiana na fields tofauti na zile za JSON body ikiwa UI ilizibadilisha baada ya signing. Baada ya tukio hilo, gateway sasa hukataa proposals ambazo hash/signature zake hazilingani na transaction iliyowasilishwa.<sup>[[3]](#references)</sup> Uthibitishaji kama huo wa hash upande wa server unapaswa kutekelezwa kwenye API yoyote ya signing-orchestration.

### Mambo muhimu ya tukio la Bybit/Safe la 2025
- Uondoaji wa fedha kutoka cold wallet ya Bybit tarehe 21 Februari 2025 (~401k ETH) ulitumia pattern ileile: Safe S3 bundle iliyoathiriwa ilijianzisha tu kwa Bybit signers na kubadilisha `operation=0` → `1`, huku `to` ikiwekwa kuelekea attacker contract iliyokuwa ime-deployiwa awali na iliyoandika slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js` iliyokuwa imehifadhiwa na Wayback inaonyesha logic iliyolenga Safe ya Bybit (`0x1db9…cf4`) na signer addresses, kisha ikarejesha mara moja bundle safi dakika mbili baada ya execution, ikifanana na mbinu ya “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (kwa mfano, `0x9622…c7242`) ilikuwa na functions rahisi `sweepETH/sweepERC20` pamoja na `transfer(address,uint256)` iliyoandika implementation slot. Utekelezaji wa `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ulibadilisha implementation ya proxy na kutoa full control.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies huhifadhi `masterCopy` kwenye **storage slot 0** na kupeleka logic yote kwake kwa delegatecall. Kwa sababu Safe inaunga mkono **`operation = 1` (delegatecall)**, transaction yoyote iliyosainiwa inaweza kuelekeza kwenye arbitrary contract na kutekeleza code yake ndani ya storage context ya proxy.<sup>[[3]](#references)</sup>

Attacker contract iliiga ERC-20 `transfer(address,uint256)` lakini badala yake ikaandika `_to` kwenye slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Njia ya utekelezaji:<sup>[[1]](#references)[[3]](#references)</sup>
1. Waathiriwa husaini `execTransaction` wakiwa na `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy huthibitisha signatures juu ya vigezo hivi.
3. Proxy hufanya delegatecall kwenda kwenye `attackerContract`; mwili wa `transfer` huandika slot 0.
4. Slot 0 (`masterCopy`) sasa inaelekeza kwenye logic inayodhibitiwa na attacker → **wallet takeover kamili na fund drain**.

### Maelezo ya Guard na version (hardening baada ya tukio)
- Transaction guards zilianzishwa katika Safe v1.3.0 na zinaweza kukagua vigezo vyote vya `execTransaction` kabla ya execution; guard inaweza kukataa `delegatecall` au kutekeleza policy kwenye destination na calldata. Bybit ilikuwa ikiendesha v1.1.1, iliyotangulia hook hii.<sup>[[2]](#references)[[6]](#references)</sup>

## Orodha ya ukaguzi wa Detection na hardening

- **UI integrity**: pin JS assets / SRI; fuatilia bundle diffs; chukulia signing UI kuwa sehemu ya trust boundary.
- **Sign-time validation**: hardware wallets zenye **EIP-712 clear-signing**; onyesha wazi `operation` na decode nested calldata. Kataa kusaini wakati `operation = 1` isipokuwa policy inaruhusu hilo.<sup>[[3]](#references)</sup>
- **Server-side hash checks**: gateways/services zinazo-relay proposals lazima zihesabu upya `safeTxHash` na zithibitishe kuwa signatures zinaendana na fields zilizowasilishwa.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: preflight rules za `to`, selectors, asset types, na kuzuia delegatecall isipokuwa kwenye flows zilizokaguliwa. Hitaji internal policy service kabla ya kubroadcast transactions zilizosainiwa kikamilifu.
- **Contract design**: epuka kufichua arbitrary delegatecall katika multisig/treasury wallets isipokuwa ni lazima kabisa. Chukulia implementation pointer yoyote kama upgrade primitive: ilinde kwa explicit access control na guard delegatecall targets/selectors; kuhamisha pointer kwenye slot nyingine pekee si defense kamili.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: toa alert kwenye delegatecall executions kutoka kwenye wallets zinazoshikilia treasury funds, na kwenye proposals zinazobadilisha `operation` kutoka kwenye typical `call` patterns.

## References

- [1] [Uchambuzi wa kiforensiki wa AnChain.AI kuhusu Safe exploit ya Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Uchambuzi wa Zero Hour Technology kuhusu bundle compromise ya Safe](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Uchambuzi wa kina wa kiufundi wa Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
