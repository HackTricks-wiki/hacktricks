# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Αλγόριθμοι Machine Learning

Το καλύτερο σημείο για να ξεκινήσετε να μαθαίνετε για την AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να καταλάβετε πώς λειτουργεί η AI, πώς να τη χρησιμοποιείτε και πώς να της επιτίθεστε:


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

Στην επόμενη σελίδα θα βρείτε τα βασικά στοιχεία κάθε component για να δημιουργήσετε ένα βασικό LLM με transformers:


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

### Πλαίσια αξιολόγησης κινδύνων AI

Δύο χρήσιμα πλαίσια για να ξεκινήσετε την αξιολόγηση των κινδύνων συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητική λίστα πλαισίων αξιολόγησης κινδύνων AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Καθοδηγούμενες από Mechanistic Interpretability Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια AI Prompts

Η χρήση της AI έχει εκτοξευθεί τα τελευταία χρόνια χάρη στα LLM, αλλά δεν είναι τέλεια και μπορεί να εξαπατηθεί με adversarial prompts. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε την AI με ασφάλεια και να γνωρίζετε πώς να της επιτεθείτε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE μέσω AI Models

Είναι πολύ συνηθισμένο οι προγραμματιστές και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε την AI με ασφάλεια και να γνωρίζετε πώς να της επιτεθείτε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με τη βοήθεια AI

Το generative video μπορεί να συνδυαστεί με virtual-camera injection και χειρισμό του camera API για την παράκαμψη αδύναμων διαδικασιών KYC, επαλήθευσης ηλικίας και ελέγχου βιομετρικής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol για AI

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν εξουσιοδότηση, συγκατάθεση, επικύρωση εισόδων εργαλείων και έλεγχο ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing και αυτοματοποιημένη ανακάλυψη ευπαθειών με τη βοήθεια AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Έλεγχος πηγαίου κώδικα και επικύρωση ευπαθειών με τη βοήθεια AI

Για έλεγχο source/sink, mobile entry-point taskflows, ελέγχους μοτίβων kernel και επικύρωση με βάση τεκμήρια:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering με τη βοήθεια AI

[Μερική ανύψωση κώδικα, εντοπισμός invariant MBA, αποκωδικοποίηση δεσμευμένη στο περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Οι agents που υποστηρίζονται από LLM μπορούν να αυτοματοποιήσουν χρονοβόρες ροές εργασιών black-box web pentesting, όταν υποστηρίζονται από παρατηρησιμότητα, orchestration, διαχείριση αυθεντικοποιημένων sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
