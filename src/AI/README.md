# AI στην κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι αλγόριθμοι μηχανικής μάθησης

Το καλύτερο σημείο εκκίνησης για να μάθετε για την AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι μηχανικής μάθησης. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί η AI, πώς να τη χρησιμοποιείτε και πώς να της επιτίθεστε:


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

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε συνιστώσας για να δημιουργήσετε ένα βασικό LLM με transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για εκτέλεση, fine-tuning, διάθεση ή δοκιμή μοντέλων, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

## Ασφάλεια AI

### Όρια εμπιστοσύνης LLM Gateway

Για την ασφάλεια του gateway, δείτε:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Μεθοδολογία ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια κινδύνου AI

Δύο χρήσιμα πλαίσια για να ξεκινήσετε την αξιολόγηση κινδύνων συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητικό κατάλογο πλαισίων κινδύνου AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Επιθέσεις adversarial με καθοδήγηση από mechanistic interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια prompt AI

Τα LLM έχουν εκτοξεύσει τη χρήση της AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν με adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε μοντέλα AI

Είναι πολύ συνηθισμένο οι προγραμματιστές και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με υποβοήθηση AI

Τα παραγόμενα βίντεο μπορούν να συνδυαστούν με έγχυση εικονικής κάμερας και χειρισμό του camera API, ώστε να παρακαμφθούν αδύναμες διαδικασίες KYC, επαλήθευσης ηλικίας και βιομετρικής ανίχνευσης ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol της AI

Το MCP (Model Context Protocol) είναι ένα ανοικτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να παρέχουν πρόσβαση σε δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν έλεγχο εξουσιοδότησης, συναίνεσης, επικύρωσης εισόδων εργαλείων και ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Πρωτόκολλο AI Agent-to-Agent (A2A)

Το A2A επιτρέπει στους agents να εντοπίζουν ο ένας τον άλλον μέσω μιας agent card και να ανταλλάσσουν εργασίες μέσω HTTP. Δοκιμάστε τις agent cards, την εξουσιοδότηση εργασιών, τα webhook ειδοποιήσεων push και τις εκτεταμένες cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Εκτεθειμένες self-hosted υπηρεσίες AI

Αποτυπώστε τα αποτυπώματα και δοκιμάστε εκτεθειμένα model runners, agent builders, διεπαφές ML demo, compute clusters και vector databases που λειτουργούν χωρίς έλεγχο ταυτότητας:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing με υποβοήθηση AI και αυτοματοποιημένος εντοπισμός ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Έλεγχος πηγαίου κώδικα και επικύρωση ευπαθειών με υποβοήθηση AI

Για έλεγχο source/sink, taskflows σημείων εισόδου σε mobile, ελέγχους μοτίβων kernel και επικύρωση με βάση τεκμήρια:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering με υποβοήθηση AI

[Μερική ανύψωση κώδικα, εντοπισμός invariant MBA, αποκωδικοποίηση εξαρτώμενη από το περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots AI για black-box web pentesting

Οι agents με LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών black-box web pentesting, όταν υποστηρίζονται από observability, orchestration, διαχείριση authenticated sessions και adversarial επικύρωση:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP — Τα 10 κορυφαία θέματα ασφάλειας μηχανικής μάθησης](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Πλαίσιο ασφαλούς AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
