# Παραβίαση ροής υπογραφής Web3 και takeover proxy Safe Delegatecall

## Επισκόπηση

Μια αλυσίδα κλοπής από cold wallet συνδύασε μια **παραβίαση εφοδιαστικής αλυσίδας του web UI του Safe{Wallet}** με ένα **on-chain primitive delegatecall που αντικατέστησε τον δείκτη implementation ενός proxy (slot 0)**. Τα βασικά συμπεράσματα είναι:

- Αν ένα dApp μπορεί να εισαγάγει κώδικα στη ροή υπογραφής, μπορεί να κάνει έναν signer να παράγει μια έγκυρη **υπογραφή EIP-712 πάνω σε πεδία που έχει επιλέξει ο attacker**, ενώ επαναφέρει τα αρχικά δεδομένα του UI ώστε οι υπόλοιποι signers να μην αντιληφθούν τίποτα.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- Τα Safe proxies αποθηκεύουν το `masterCopy` (implementation) στο **storage slot 0**. Ένα delegatecall προς ένα contract που γράφει στο slot 0 ουσιαστικά «αναβαθμίζει» το Safe σε logic του attacker, παρέχοντας πλήρη έλεγχο του wallet.<sup>[[3]](#references)</sup>

## Εκτός αλυσίδας: Στοχευμένη μετάλλαξη υπογραφής στο Safe{Wallet}

Ένα παραποιημένο Safe bundle (`_app-*.js`) στόχευε επιλεκτικά συγκεκριμένες διευθύνσεις Safe και signer. Η injected logic εκτελούνταν ακριβώς πριν από την κλήση υπογραφής:<sup>[[1]](#references)[[3]](#references)</sup>
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
- **Context-gated**: hard-coded allowlists για victim Safes/signers απέτρεπαν τον θόρυβο και μείωναν την ανίχνευση.<sup>[[1]](#references)[[3]](#references)</sup>
- **Last-moment mutation**: τα πεδία (`to`, `data`, `operation`, gas) αντικαθίσταντο αμέσως πριν από το `signTransaction` και έπειτα επαναφέρονταν, έτσι τα proposal payloads στο UI φαίνονταν αθώα, ενώ οι υπογραφές αντιστοιχούσαν στο payload του attacker.<sup>[[3]](#references)</sup>
- **EIP-712 opacity**: τα wallets εμφάνιζαν structured data, αλλά δεν έκαναν decode το nested calldata ούτε επισήμαιναν το `operation = delegatecall`, με αποτέλεσμα το mutated message να υπογράφεται ουσιαστικά στα τυφλά.<sup>[[3]](#references)[[4]](#references)</sup>

### Συνάφεια με το Gateway validation
Τα Safe proposals υποβάλλονται στο **Safe Client Gateway**.<sup>[[5]](#references)</sup> Πριν από την εφαρμογή hardened checks, το gateway μπορούσε να αποδεχτεί ένα proposal όπου το `safeTxHash`/signature αντιστοιχούσε σε διαφορετικά πεδία από εκείνα του JSON body, αν το UI τα ξαναέγραφε μετά την υπογραφή. Μετά το incident, το gateway απορρίπτει πλέον proposals των οποίων το hash/signature δεν αντιστοιχεί στο submitted transaction.<sup>[[3]](#references)</sup> Παρόμοιο server-side hash verification πρέπει να επιβάλλεται σε κάθε signing-orchestration API.

### Βασικά σημεία του Bybit/Safe incident του 2025
- Το drain του Bybit cold wallet στις 21 Φεβρουαρίου 2025 (~401k ETH) επαναχρησιμοποίησε το ίδιο pattern: ένα compromised Safe S3 bundle ενεργοποιούνταν μόνο για Bybit signers και άλλαζε το `operation=0` → `1`, δείχνοντας το `to` σε ένα pre-deployed attacker contract που γράφει στο slot 0.<sup>[[1]](#references)[[3]](#references)</sup>
- Το Wayback-cached `_app-52c9031bfa03da47.js` δείχνει ότι η λογική βασιζόταν στο Safe του Bybit (`0x1db9…cf4`) και σε signer addresses και στη συνέχεια έκανε αμέσως rollback σε clean bundle δύο λεπτά μετά την εκτέλεση, αναπαράγοντας το trick “mutate → sign → restore”.<sup>[[1]](#references)[[2]](#references)</sup>
- Το malicious contract (π.χ. `0x9622…c7242`) περιείχε απλές functions `sweepETH/sweepERC20` και ένα `transfer(address,uint256)` που γράφει στο implementation slot. Η εκτέλεση του `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` άλλαξε το proxy implementation και παρείχε πλήρη έλεγχο.<sup>[[1]](#references)[[3]](#references)</sup>

## On-chain: Delegatecall proxy takeover μέσω slot collision

Τα Safe proxies διατηρούν το `masterCopy` στο **storage slot 0** και κάνουν delegate όλη τη λογική σε αυτό. Επειδή το Safe υποστηρίζει **`operation = 1` (delegatecall)**, κάθε signed transaction μπορεί να δείξει σε ένα arbitrary contract και να εκτελέσει τον κώδικά του στο storage context του proxy.<sup>[[3]](#references)</sup>

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
4. Το slot 0 (`masterCopy`) δείχνει πλέον σε logic που ελέγχεται από τον attacker → **πλήρης takeover του wallet και drain των funds**.

### Σημειώσεις για Guard και version (hardening μετά το incident)
- Τα transaction guards εισήχθησαν στο Safe v1.3.0 και μπορούν να ελέγχουν όλες τις παραμέτρους του `execTransaction` πριν από την εκτέλεση· ένα guard μπορεί να απορρίψει το `delegatecall` ή να επιβάλει policy στο destination και το calldata. Το Bybit χρησιμοποιούσε την v1.1.1, η οποία προηγείται αυτού του hook.<sup>[[2]](#references)[[6]](#references)</sup>

## Detection & hardening checklist

- **Ακεραιότητα UI**: κάντε pin τα JS assets / SRI· παρακολουθείτε τις διαφορές των bundles· αντιμετωπίζετε το signing UI ως μέρος του trust boundary.
- **Validation κατά την υπογραφή**: hardware wallets με **EIP-712 clear-signing**· να εμφανίζουν ρητά το `operation` και να κάνουν decode το nested calldata. Απορρίπτετε την υπογραφή όταν `operation = 1`, εκτός αν το επιτρέπει η policy.<sup>[[3]](#references)</sup>
- **Έλεγχοι hash στην πλευρά του server**: gateways/services που κάνουν relay proposals πρέπει να υπολογίζουν ξανά το `safeTxHash` και να επικυρώνουν ότι οι υπογραφές αντιστοιχούν στα submitted fields.<sup>[[3]](#references)</sup>
- **Policy/allowlists**: κανόνες preflight για `to`, selectors, asset types, και απαγόρευση του delegatecall εκτός από vetted flows. Απαιτείτε ένα internal policy service πριν από το broadcasting πλήρως υπογεγραμμένων transactions.
- **Σχεδιασμός contract**: αποφεύγετε την έκθεση arbitrary delegatecall σε multisig/treasury wallets, εκτός αν είναι απολύτως απαραίτητο. Αντιμετωπίζετε οποιονδήποτε implementation pointer ως upgrade primitive: προστατεύετέ τον με explicit access control και guard στα delegatecall targets/selectors· η μετακίνηση του pointer σε άλλο slot από μόνη της δεν αποτελεί πλήρη άμυνα.<sup>[[3]](#references)[[6]](#references)</sup>
- **Monitoring**: δημιουργείτε alerts για delegatecall executions από wallets που διατηρούν treasury funds, καθώς και για proposals που αλλάζουν το `operation` από τυπικά patterns `call`.

## References

- [1] [Forensic ανάλυση του Bybit Safe exploit από την AnChain.AI](https://www.anchain.ai/blog/bybit)
- [2] [Ανάλυση του Safe bundle compromise από τη Zero Hour Technology](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [3] [Σε βάθος technical analysis του Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [4] [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [5] [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)
- [6] [Changelog του Safe smart account v1.3.0 (GitHub)](https://github.com/safe-fndn/safe-smart-account/blob/main/CHANGELOG.md)
{{#include ../../banners/hacktricks-training.md}}
