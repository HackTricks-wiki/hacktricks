# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Αλγόριθμοι Μηχανικής Μάθησης

Το καλύτερο σημείο για να ξεκινήσετε να μαθαίνετε για το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι μηχανικής μάθησης. Αυτό θα σας βοηθήσει να καταλάβετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

Στην παρακάτω σελίδα θα βρείτε τα βασικά στοιχεία κάθε συστατικού που χρειάζεται για να δημιουργήσετε ένα βασικό LLM χρησιμοποιώντας transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ασφάλεια AI

### Μεθοδολογία Ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια Κινδύνου AI

Δύο χρήσιμα πλαίσια για να ξεκινήσετε την αξιολόγηση του κινδύνου συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και όχι μια εξαντλητική λίστα πλαισίων κινδύνου AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ασφάλεια Prompt AI

Τα LLM έχουν οδηγήσει σε ραγδαία εξάπλωση της χρήσης AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Πρόκειται για ένα πολύ σημαντικό θέμα, ώστε να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε Μοντέλα AI

Είναι πολύ συνηθισμένο οι developers και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Πρόκειται για ένα πολύ σημαντικό θέμα, ώστε να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με τη βοήθεια AI

Το generative video μπορεί να συνδυαστεί με virtual-camera injection και χειρισμό του camera API, ώστε να παρακαμφθούν αδύναμες διαδικασίες KYC, επαλήθευσης ηλικίας και βιομετρικού ελέγχου ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol του AI

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Καθώς οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν έλεγχο εξουσιοδότησης, συναίνεσης, επικύρωσης εισόδων εργαλείων και ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing με τη βοήθεια AI και Αυτοματοποιημένος Εντοπισμός Ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Αντίστροφη Μηχανική με τη βοήθεια AI

[Μερική ανύψωση, εντοπισμός invariant MBA, αποκωδικοποίηση εξαρτώμενη από το περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Οι agents που υποστηρίζονται από LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασίας web black-box pentesting, όταν υποστηρίζονται από observability, orchestration, διαχείριση authenticated sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 Ασφάλειας Μηχανικής Μάθησης](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Πλαίσιο Ασφαλούς AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
