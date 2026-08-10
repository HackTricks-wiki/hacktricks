# Compromise ya Web3 Signing Workflow na Takeover ya Safe Delegatecall Proxy

## Muhtasari

Mlolongo wa wizi wa cold-wallet ulihusisha **supply-chain compromise ya Safe{Wallet} web UI** pamoja na **on-chain delegatecall primitive iliyoandika upya implementation pointer ya proxy (slot 0)**. Mambo muhimu ya kuzingatia ni:

- Ikiwa dApp inaweza kuingiza code kwenye signing path, inaweza kumfanya signer atoe **EIP-712 signature yenye fields zilizochaguliwa na attacker** huku ikirejesha data ya awali ya UI ili signers wengine wasitambue.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Safe proxies huhifadhi `masterCopy` (implementation) kwenye **storage slot 0**. Delegatecall kwenda kwenye contract inayoandika kwenye slot 0 kwa ufanisi “hu-upgrade” Safe ili itumie attacker logic, na hivyo kumpa attacker control kamili ya wallet.<sup>[[3]](#references)</sup>

## Off-chain: Mabadiliko lengwa ya signing katika Safe{Wallet}

Safe bundle iliyotampered (`_app-*.js`) ilishambulia kwa kuchagua Safe + signer addresses maalum. Logic iliyoingizwa ilitekelezwa mara moja kabla ya signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: allowlists zilizowekwa moja kwa moja za Safe/signers wa victim zilizuia noise na kupunguza detection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) zilibadilishwa mara moja kabla ya `signTransaction`, kisha kurudishwa, hivyo proposal payloads kwenye UI zilionekana kuwa salama huku signatures zikilingana na attacker payload.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: wallets zilionyesha structured data lakini hazikufanya decode ya nested calldata au kuonyesha wazi `operation = delegatecall`, hivyo ujumbe uliobadilishwa ulisainiwa bila kuonekana kikamilifu.<sup>[[3]](#references)[[4]](#references)</sup>

### Umuhimu wa Gateway validation
Safe proposals huwasilishwa kwa **Safe Client Gateway**.<sup>[[5]](#references)</sup> Kabla ya kuwekwa kwa hardened checks, gateway ingeweza kukubali proposal ambayo `safeTxHash`/signature ilihusiana na fields tofauti na zilizo kwenye JSON body ikiwa UI ilizibadilisha baada ya signing. Baada ya incident hiyo, gateway sasa hukataa proposals ambazo hash/signature zake hazilingani na transaction iliyowasilishwa.<sup>[[3]](#references)</sup> Uthibitishaji kama huo wa hash upande wa server unapaswa kutekelezwa kwenye signing-orchestration API yoyote.

### Mambo muhimu ya 2025 Bybit/Safe incident
- Cold-wallet drain ya Bybit ya Februari 21, 2025 (~401k ETH) ilitumia tena pattern ileile: Safe S3 bundle iliyoathiriwa iliwashwa tu kwa Bybit signers na kubadilisha `operation=0` → `1`, huku `to` ikiwekwa kwenye attacker contract iliyokuwa ime-deployiwa awali na kuandika slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js` iliyohifadhiwa kwenye Wayback inaonyesha logic iliyokuwa keyed kwenye Safe ya Bybit (`0x1db9…cf4`) na signer addresses, kisha ikarudishwa mara moja kwenye bundle safi dakika mbili baada ya execution, ikifuata hila ya “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (kwa mfano, `0x9622…c7242`) ilikuwa na functions rahisi `sweepETH/sweepERC20` pamoja na `transfer(address,uint256)` iliyoandika implementation slot. Utekelezaji wa `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ulihamisha proxy implementation na kutoa full control.<sup>[[1]](#references)[[3]](#references)</sup>

## Kwenye on-chain: Delegatecall proxy takeover kupitia slot collision

Safe proxies huhifadhi `masterCopy` kwenye **storage slot 0** na hupeleka logic yote kwake kupitia delegatecall. Kwa sababu Safe inasaidia **`operation = 1` (delegatecall)**, transaction yoyote iliyosainiwa inaweza kuelekeza kwenye contract yoyote na kutekeleza code yake katika storage context ya proxy.<sup>[[3]](#references)</sup>

Attacker contract iliiga `transfer(address,uint256)` ya ERC-20 lakini badala yake ikaandika `_to` kwenye slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Njia ya utekelezaji:<sup>[[1]](#references)[[3]](#references)</sup>
1. Victims husaini `execTransaction` yenye `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe masterCopy huthibitisha signatures juu ya parameters hizi.
3. Proxy hufanya delegatecall kwenda `attackerContract`; mwili wa `transfer` huandika slot 0.
4. Slot 0 (`masterCopy`) sasa huelekeza kwenye logic inayodhibitiwa na attacker → **utekaji kamili wa wallet na kunyonya fedha**.

### Vidokezo vya Guard na version (ufanyaji wa hardening baada ya tukio)
- Transaction guards zilianzishwa katika Safe v1.3.0 na zinaweza kukagua parameters zote za `execTransaction` kabla ya execution; guard inaweza kukataa `delegatecall` au kutekeleza policy kwenye destination na calldata. Bybit ilitumia v1.1.1, ambayo ilitangulia hook hii.<sup>[[2]](#references)[[6]](#references)</sup>

## Orodha ya ukaguzi wa Detection na hardening

- **Uadilifu wa UI**: pin JS assets / SRI; fuatilia tofauti za bundle; chukulia signing UI kama sehemu ya trust boundary.
- **Uthibitishaji wakati wa kusaini**: hardware wallets zenye **EIP-712 clear-signing**; onyesha wazi `operation` na decode nested calldata. Kataa kusaini wakati `operation = 1` isipokuwa policy inaruhusu.<sup>[[3]](#references)</sup>
- **Ukaguzi wa hash upande wa server**: gateways/services zinazo-relay proposals lazima zihesabu upya `safeTxHash` na kuthibitisha kuwa signatures zinaendana na fields zilizowasilishwa.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: sheria za preflight za `to`, selectors, asset types, na kuzuia delegatecall isipokuwa kwenye flows zilizokaguliwa. Hitaji internal policy service kabla ya kubroadcast fully signed transactions.
- **Muundo wa Contract**: epuka kufichua delegatecall ya kiholela katika multisig/treasury wallets isipokuwa ni lazima kabisa. Chukulia pointer yoyote ya implementation kama upgrade primitive: ilinde kwa explicit access control na guard delegatecall targets/selectors; kuhamisha pointer kwenye slot nyingine pekee si defense kamili.<sup>[[3]](#references)[[6]](#references)</sup>
- **Ufuatiliaji**: toa alert kuhusu delegatecall executions kutoka kwenye wallets zinazoshikilia treasury funds, na kuhusu proposals zinazobadilisha `operation` kutoka kwenye patterns za kawaida za `call`.

## References

- [1] [Uchambuzi wa kiuchunguzi wa AnChain.AI kuhusu Safe exploit ya Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Uchambuzi wa Zero Hour Technology kuhusu Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Uchambuzi wa kina wa kiufundi wa Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Safe smart account v1.3.0 changelog (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
