# Compromise ya Web3 Signing Workflow & Takeover ya Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Mnyororo wa wizi wa cold-wallet uliunganisha **supply-chain compromise ya Safe{Wallet} web UI** na **on-chain delegatecall primitive iliyoandika upya implementation pointer ya proxy (slot 0)**. Mambo muhimu ya kuzingatia ni:

- Ikiwa dApp inaweza kuingiza code kwenye signing path, inaweza kumfanya signer atengeneze **EIP-712 signature juu ya fields zilizochaguliwa na attacker**<sup>[[4]](#references)</sup> huku ikirejesha UI data ya awali ili signers wengine wasitambue.
- Safe proxies huhifadhi `masterCopy` (implementation) kwenye **storage slot 0**. Delegatecall kwa contract inayoandika kwenye slot 0 kwa ufanisi “hu-upgrade” Safe iwe attacker logic, na hivyo kutoa udhibiti kamili wa wallet.

## Off-chain: Targeted signing mutation katika Safe{Wallet}

Safe bundle iliyochezewa (`_app-*.js`) ililenga kwa kuchagua anwani maalum za Safe + signer. Injected logic ilitekelezwa mara moja kabla ya signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Linalodhibitiwa na muktadha**: allowlists zilizowekwa moja kwa moja za Safes/signers wa mwathiriwa zilizuia noise na kupunguza detection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mabadiliko ya dakika ya mwisho**: fields (`to`, `data`, `operation`, gas) ziliandikwa upya mara moja kabla ya `signTransaction`, kisha kurejeshwa, hivyo proposal payloads kwenye UI zilionekana kuwa salama huku signatures zikilingana na attacker payload.
- **Opacity ya EIP-712**: wallets zilionyesha structured data lakini hazikufanya decode nested calldata wala kuonyesha wazi `operation = delegatecall`, hivyo ujumbe uliobadilishwa uliishia kusainiwa bila kuonekana kikamilifu.

### Umuhimu wa uthibitishaji wa Gateway
Safe proposals hutumwa kwenye **Safe Client Gateway**.<sup>[[5]](#references)</sup> Kabla ya hardening checks, gateway ingeweza kukubali proposal ambayo `safeTxHash`/signature yake ililingana na fields tofauti na zile za JSON body ikiwa UI ilikuwa imeziandika upya baada ya signing. Baada ya incident, gateway sasa hukataa proposals ambazo hash/signature zake hazilingani na transaction iliyowasilishwa. Uthibitishaji kama huo wa hash upande wa server unapaswa kutekelezwa kwenye API yoyote ya signing-orchestration.

### Mambo muhimu ya incident ya Bybit/Safe ya 2025
- Uvujaji wa cold-wallet wa Bybit wa Februari 21, 2025 (~401k ETH) ulitumia tena pattern ileile: Safe S3 bundle iliyoathiriwa ilichochewa tu kwa Bybit signers na kubadilisha `operation=0` → `1`, huku `to` ikielekezwa kwenye attacker contract iliyokuwa ime-deployiwa awali na ambayo huandika slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js` iliyohifadhiwa na Wayback inaonyesha logic iliyolenga Safe ya Bybit (`0x1db9…cf4`) na signer addresses, kisha ikarejeshwa mara moja kwenye clean bundle dakika mbili baada ya execution, ikifanana na mbinu ya “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (kwa mfano, `0x9622…c7242`) ilikuwa na functions rahisi `sweepETH/sweepERC20` pamoja na `transfer(address,uint256)` iliyoandika implementation slot. Execution ya `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ilibadilisha proxy implementation na kutoa full control.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover kupitia slot collision

Safe proxies huhifadhi `masterCopy` kwenye **storage slot 0** na kupeleka logic yote kwake kupitia delegatecall. Kwa kuwa Safe inasaidia **`operation = 1` (delegatecall)**, signed transaction yoyote inaweza kuelekeza kwenye arbitrary contract na kutekeleza code yake ndani ya storage context ya proxy.<sup>[[3]](#references)</sup>

Attacker contract iliiga ERC-20 `transfer(address,uint256)` lakini badala yake ikaandika `_to` kwenye slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
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
4. Slot 0 (`masterCopy`) sasa inaelekeza kwenye logic inayodhibitiwa na attacker → **full wallet takeover na fund drain**.

### Maelezo ya Guard na version (hardening baada ya tukio)
- Safes >= v1.3.0 zinaweza kusakinisha **Guard** ya kuzuia `delegatecall` au kutekeleza ACLs kwenye `to`/selectors; Bybit ilikuwa ikiendesha v1.1.1, kwa hiyo hakukuwa na Guard hook. Contract zinahitaji ku-upgradeiwa (na owners kuongezwa tena) ili kupata control plane hii.

## Checklist ya detection na hardening

- **UI integrity**: pin JS assets / SRI; fuatilia bundle diffs; ichukulie signing UI kuwa sehemu ya trust boundary.
- **Sign-time validation**: hardware wallets zenye **EIP-712 clear-signing**; onyesha wazi `operation` na decode nested calldata. Kataa kusaini wakati `operation = 1`, isipokuwa policy inaruhusu.
- **Server-side hash checks**: gateways/services zinazo-relay proposals lazima zihesabu upya `safeTxHash` na zithibitishe kuwa signatures zinaendana na fields zilizowasilishwa.
- **Policy/allowlists**: preflight rules za `to`, selectors, asset types, na kuzuia delegatecall isipokuwa kwenye flows zilizothibitishwa. Inahitaji internal policy service kabla ya kubroadcast transactions zilizosainiwa kikamilifu.
- **Contract design**: epuka kuweka arbitrary delegatecall wazi katika multisig/treasury wallets isipokuwa ikiwa ni lazima kabisa. Weka upgrade pointers mbali na slot 0 au zilinde kwa upgrade logic na access control zilizo wazi.
- **Monitoring**: toa alert kuhusu delegatecall executions kutoka kwenye wallets zinazoshikilia treasury funds, na kuhusu proposals zinazobadilisha `operation` kutoka kwenye patterns za kawaida za `call`.

## References

- [1] [Uchambuzi wa forensic wa AnChain.AI kuhusu Safe exploit ya Bybit](https://www.anchain.ai/blog/bybit)
- [2] [Uchambuzi wa Zero Hour Technology kuhusu compromise ya Safe bundle](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Uchambuzi wa kina wa kiufundi wa Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
