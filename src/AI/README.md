# Η AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Αλγόριθμοι Machine Learning

Το καλύτερο σημείο εκκίνησης για να μάθετε για την AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί η AI, πώς να τη χρησιμοποιείτε και πώς να της επιτίθεστε:


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

Στην ακόλουθη σελίδα θα βρείτε τις βασικές πληροφορίες για κάθε στοιχείο που απαιτείται για τη δημιουργία ενός βασικού LLM με transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για την εκτέλεση, το fine-tuning, την παροχή ή τη δοκιμή μοντέλων, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

## Ασφάλεια AI

### Όρια εμπιστοσύνης LLM Gateway

Για την ασφάλεια των gateway, ανατρέξτε στο:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Μεθοδολογία ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια κινδύνων AI

Δύο χρήσιμα πλαίσια εκκίνησης για την αξιολόγηση κινδύνων συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητικό κατάλογο πλαισίων κινδύνων AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Επιθέσεις adversarial με καθοδήγηση από mechanistic interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια prompts AI

Τα LLM έχουν οδηγήσει σε εκρηκτική αύξηση της χρήσης της AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να εξαπατηθούν με adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε μοντέλα AI

Είναι πολύ συνηθισμένο για προγραμματιστές και εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, μόνο η φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε την AI με ασφάλεια και πώς να της επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με τη βοήθεια AI

Τα generative video μπορούν να συνδυαστούν με εισαγωγή virtual camera και χειρισμό του camera API για την παράκαμψη αδύναμων ροών εργασίας KYC, επαλήθευσης ηλικίας και βιομετρικού ελέγχου ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol για AI

Το MCP (Model Context Protocol) είναι ένα ανοικτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν εξουσιοδότηση, συγκατάθεση, επικύρωση εισόδων εργαλείων και έλεγχο ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing και αυτοματοποιημένος εντοπισμός ευπαθειών με τη βοήθεια AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Έλεγχος πηγαίου κώδικα και επικύρωση ευπαθειών με τη βοήθεια AI

Για τον έλεγχο source/sink, τις ροές εργασιών taskflow των mobile entry points, τους ελέγχους μοτίβων kernel και την επικύρωση βάσει τεκμηρίων:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering με τη βοήθεια AI

[Partial lifting, εντοπισμός invariant MBA, αποκωδικοποίηση δεσμευμένη στο περιβάλλον και επικύρωση αυτοματοποιημένου extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots AI pentester για web black-box

Οι agents που υποστηρίζονται από LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών web black-box pentesting, όταν υποστηρίζονται από observability, orchestration, διαχείριση πιστοποιημένων sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Ασφαλές AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
