# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Αλγόριθμοι Μηχανικής Μάθησης

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

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε στοιχείου που χρειάζεται για να δημιουργήσετε ένα βασικό LLM με transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ασφάλεια AI

### Μεθοδολογία Ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια Διαχείρισης Κινδύνων AI

Δύο χρήσιμα πλαίσια για την αξιολόγηση του κινδύνου συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητικό κατάλογο πλαισίων διαχείρισης κινδύνων AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Καθοδηγούμενες από Mechanistic Interpretability Adversarial Επιθέσεις

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια Prompts AI

Τα LLM έχουν οδηγήσει σε εκρηκτική αύξηση της χρήσης AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε την AI με ασφάλεια και να γνωρίζετε πώς να της επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε Μοντέλα AI

Είναι πολύ συνηθισμένο οι developers και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε την AI με ασφάλεια και να γνωρίζετε πώς να της επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με υποβοήθηση AI

Το generative video μπορεί να συνδυαστεί με virtual-camera injection και χειρισμό του camera API για να παρακαμφθούν ανεπαρκείς διαδικασίες KYC, επαλήθευσης ηλικίας και βιομετρικού ελέγχου ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

Το MCP (Model Context Protocol) είναι ένα ανοικτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν έλεγχο εξουσιοδότησης, συναίνεσης, επικύρωσης εισόδων εργαλείων και ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing με υποβοήθηση AI και Αυτοματοποιημένος Εντοπισμός Ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering με υποβοήθηση AI

[Μερική ανύψωση κώδικα, ανίχνευση invariant MBA, αποκωδικοποίηση δεσμευμένη σε περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Οι agents που υποστηρίζονται από LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασίας black-box web pentesting, όταν διαθέτουν observability, orchestration, χειρισμό αυθεντικοποιημένων sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 για την Ασφάλεια της Μηχανικής Μάθησης](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Πλαίσιο Ασφαλούς AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
