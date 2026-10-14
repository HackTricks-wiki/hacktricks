# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι αλγόριθμοι μηχανικής μάθησης

Το καλύτερο σημείο για να ξεκινήσετε να μαθαίνετε για την AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι μηχανικής μάθησης. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί η AI, πώς να τη χρησιμοποιείτε και πώς να της επιτίθεστε:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Αρχιτεκτονική LLM

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε συστατικού για να δημιουργήσετε ένα βασικό LLM με transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για να εκτελέσετε, να κάνετε fine-tuning, να διαθέσετε ή να δοκιμάσετε μοντέλα, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

## Ασφάλεια AI

### Μεθοδολογία ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια αξιολόγησης κινδύνου AI

Δύο χρήσιμα πλαίσια για να ξεκινήσετε την αξιολόγηση κινδύνων συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητικό κατάλογο πλαισίων κινδύνου AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarial επιθέσεις καθοδηγούμενες από mechanistic interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια prompt AI

Τα LLM έχουν οδηγήσει σε ραγδαία αύξηση της χρήσης της AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε μοντέλα AI

Είναι πολύ συνηθισμένο οι προγραμματιστές και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με υποβοήθηση AI

Η δημιουργία βίντεο μπορεί να συνδυαστεί με έγχυση εικονικής κάμερας και χειρισμό του camera API για την παράκαμψη αδύναμων διαδικασιών KYC, επαλήθευσης ηλικίας και ελέγχου ζωντανής παρουσίας με βιομετρικά στοιχεία:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol της AI

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν έλεγχο εξουσιοδότησης, συγκατάθεσης, επικύρωσης εισόδων εργαλείων και ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing με υποβοήθηση AI και αυτοματοποιημένος εντοπισμός ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse engineering με υποβοήθηση AI

[Μερική ανύψωση κώδικα, ανίχνευση invariant MBA, αποκωδικοποίηση δεσμευμένη στο περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web black-box AI pentester bots

Οι agents που υποστηρίζονται από LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών web black-box pentesting, όταν υποστηρίζονται από παρατηρησιμότητα, ενορχήστρωση, διαχείριση αυθεντικοποιημένων sessions και adversarial επικύρωση:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: Τα 10 σημαντικότερα ζητήματα ασφάλειας στη μηχανική μάθηση](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Ασφαλές πλαίσιο AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
