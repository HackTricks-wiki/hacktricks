# Παραβίαση της ροής υπογραφής Web3 & takeover Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια αλυσίδα κλοπής cold-wallet συνδύασε έναν **supply-chain compromise του web UI του Safe{Wallet}** με ένα **on-chain delegatecall primitive που overwrote τον implementation pointer ενός proxy (slot 0)**. Τα βασικά συμπεράσματα είναι:

- Αν ένα dApp μπορεί να inject κώδικα στη signing path, μπορεί να κάνει έναν signer να παράγει μια έγκυρη **EIP-712 signature πάνω σε fields που επιλέγει ο attacker**<sup>[[4]](#references)</sup>, ενώ επαναφέρει τα αρχικά UI data ώστε οι υπόλοιποι signers να μην αντιληφθούν τίποτα.
- Τα Safe proxies αποθηκεύουν το `masterCopy` (implementation) στο **storage slot 0**. Ένα delegatecall προς contract που γράφει στο slot 0 ουσιαστικά κάνει “upgrade” το Safe σε attacker logic, παρέχοντας πλήρη έλεγχο του wallet.

## Off-chain: Στοχευμένη μετάλλαξη signing στο Safe{Wallet}

Ένα παραποιημένο Safe bundle (`_app-*.js`) επιτέθηκε επιλεκτικά σε συγκεκριμένες διευθύνσεις Safe + signer. Η injected logic εκτελέστηκε ακριβώς πριν από το signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
### Ιδιότητες της επίθεσης
- **Context-gated**: hard-coded allowlists για victim Safes/signers περιόριζαν τον θόρυβο και μείωναν την ανίχνευση.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: τα πεδία (`to`, `data`, `operation`, gas) αντικαθίσταντο αμέσως πριν από το `signTransaction` και στη συνέχεια επαναφέρονταν, ώστε τα proposal payloads στο UI να φαίνονται αβλαβή, ενώ οι signatures να αντιστοιχούν στο payload του attacker.
- **EIP-712 opacity**: τα wallets εμφάνιζαν structured data, αλλά δεν έκαναν decode το nested calldata ούτε επισήμαιναν το `operation = delegatecall`, με αποτέλεσμα το mutated message να γίνεται effectively blind-signed.

### Σημασία της επικύρωσης στο Gateway
Τα Safe proposals υποβάλλονται στο **Safe Client Gateway**.<sup>[[5]](#references)</sup> Πριν από την εφαρμογή hardened checks, το gateway μπορούσε να αποδεχτεί ένα proposal όπου το `safeTxHash`/signature αντιστοιχούσε σε διαφορετικά fields από εκείνα του JSON body, εάν το UI τα ξαναέγραφε μετά το signing. Μετά το incident, το gateway απορρίπτει πλέον proposals των οποίων το hash/signature δεν αντιστοιχεί στο submitted transaction. Αντίστοιχη server-side hash verification θα πρέπει να επιβάλλεται σε κάθε signing-orchestration API.

### Κύρια σημεία του Bybit/Safe incident του 2025
- Το drain του Bybit cold-wallet στις 21 Φεβρουαρίου 2025 (~401k ETH) επανέλαβε το ίδιο pattern: ένα compromised Safe S3 bundle ενεργοποιούνταν μόνο για Bybit signers και άλλαζε το `operation=0` σε `1`, δείχνοντας το `to` σε ένα pre-deployed attacker contract που γράφει στο slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Το Wayback-cached `_app-52c9031bfa03da47.js` δείχνει ότι η λογική βασιζόταν στο Safe του Bybit (`0x1db9…cf4`) και σε signer addresses και, στη συνέχεια, επαναφερόταν αμέσως σε clean bundle δύο λεπτά μετά την εκτέλεση, αντιγράφοντας το “mutate → sign → restore” trick.<sup>[[1]](#references)[[2]](#references)</sup>
- Το malicious contract (π.χ. `0x9622…c7242`) περιείχε απλές functions `sweepETH/sweepERC20` καθώς και μια `transfer(address,uint256)` που γράφει στο implementation slot. Η εκτέλεση του `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` άλλαζε το proxy implementation και παρείχε πλήρη έλεγχο.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover μέσω slot collision

Τα Safe proxies διατηρούν το `masterCopy` στο **storage slot 0** και κάνουν delegate όλη τη λογική σε αυτό. Επειδή το Safe υποστηρίζει **`operation = 1` (delegatecall)**, οποιοδήποτε signed transaction μπορεί να δείξει σε ένα arbitrary contract και να εκτελέσει τον κώδικά του στο storage context του proxy.<sup>[[3]](#references)</sup>

Ένα attacker contract μιμήθηκε ένα ERC-20 `transfer(address,uint256)`, αλλά αντί γι’ αυτό έγραψε το `_to` στο slot 0:<sup>[[1]](#references)[[3]](#references)</sup>
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Διαδρομή εκτέλεσης:<sup>[[1]](#references)[[3]](#references)</sup>
1. Τα θύματα υπογράφουν `execTransaction` με `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Το Safe masterCopy επικυρώνει τις υπογραφές πάνω σε αυτές τις παραμέτρους.
3. Το Proxy εκτελεί delegatecall στο `attackerContract`· το σώμα του `transfer` γράφει στο slot 0.
4. Το slot 0 (`masterCopy`) δείχνει πλέον σε logic υπό τον έλεγχο του attacker → **πλήρης κατάληψη του wallet και drain των κεφαλαίων**.

### Σημειώσεις για Guard και version (hardening μετά το incident)
- Τα Safes >= v1.3.0 μπορούν να εγκαταστήσουν ένα **Guard** για να απορρίπτει `delegatecall` ή να επιβάλλει ACLs στα `to`/selectors· το Bybit χρησιμοποιούσε την v1.1.1, επομένως δεν υπήρχε Guard hook. Απαιτείται αναβάθμιση των contracts (και εκ νέου προσθήκη των owners) για την απόκτηση αυτού του control plane.

## Checklist για detection και hardening

- **Ακεραιότητα UI**: κάντε pin τα JS assets / SRI· παρακολουθείτε τις διαφορές στα bundles· αντιμετωπίζετε το signing UI ως μέρος του trust boundary.
- **Επικύρωση κατά το signing**: hardware wallets με **EIP-712 clear-signing**· εμφανίζετε ρητά το `operation` και κάνετε decode το nested calldata. Απορρίπτετε το signing όταν `operation = 1`, εκτός αν το επιτρέπει η policy.
- **Έλεγχοι hash στην πλευρά του server**: τα gateways/services που κάνουν relay proposals πρέπει να επανυπολογίζουν το `safeTxHash` και να επικυρώνουν ότι οι υπογραφές αντιστοιχούν στα submitted fields.
- **Policies/allowlists**: κανόνες preflight για `to`, selectors, asset types, και απαγόρευση του delegatecall εκτός από vetted flows. Απαιτείτε ένα internal policy service πριν από το broadcasting πλήρως υπογεγραμμένων transactions.
- **Σχεδιασμός contract**: αποφεύγετε την έκθεση arbitrary delegatecall σε multisig/treasury wallets, εκτός αν είναι απολύτως απαραίτητο. Τοποθετείτε τα upgrade pointers μακριά από το slot 0 ή προστατεύετέ τα με explicit upgrade logic και access control.
- **Monitoring**: δημιουργείτε alert για executions delegatecall από wallets που διατηρούν treasury funds, καθώς και για proposals που αλλάζουν το `operation` από συνηθισμένα patterns `call`.

## Αναφορές

- [1] [Forensic breakdown του Bybit Safe exploit από την AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Ανάλυση του Safe bundle compromise από τη Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Εμπεριστατωμένη technical analysis του Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
