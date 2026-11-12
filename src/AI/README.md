# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι αλγόριθμοι Machine Learning

Το καλύτερο σημείο για να ξεκινήσετε να μαθαίνετε για το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

### Προετοιμασία και αξιολόγηση δεδομένων μοντέλων

Για διαχωρισμούς dataset, κλασικές μετρικές και επιθέσεις στην πλευρά των απαντήσεων σε βαθμολόγηση με βάση LLM, δείτε [προετοιμασία και αξιολόγηση δεδομένων μοντέλων](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Αρχιτεκτονική LLM

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε συστατικού για να δημιουργήσετε ένα βασικό LLM με transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για την εκτέλεση, το fine-tuning, το serving ή τη δοκιμή μοντέλων, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

## Ασφάλεια AI

### Όρια εμπιστοσύνης LLM Gateway

Για την ασφάλεια gateway, δείτε:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Μεθοδολογία ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια κινδύνου AI

Δύο χρήσιμα πλαίσια για να ξεκινήσετε την αξιολόγηση του κινδύνου συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και όχι μια εξαντλητική λίστα πλαισίων κινδύνου AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Επιθέσεις adversarial με καθοδήγηση από μηχανιστική ερμηνευσιμότητα

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Ασφάλεια prompts AI

Τα LLM έχουν οδηγήσει σε ραγδαία αύξηση της χρήσης του AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να εξαπατηθούν από adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε μοντέλα AI

Είναι πολύ συνηθισμένο για προγραμματιστές και εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, και μόνο η φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με τη βοήθεια AI

Τα βίντεο που δημιουργούνται με AI μπορούν να συνδυαστούν με έγχυση virtual camera και χειρισμό camera API για την παράκαμψη αδύναμων διαδικασιών KYC, επαλήθευσης ηλικίας και ελέγχου ζωντανής παρουσίας με βιομετρικά στοιχεία:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Καθώς οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν εξουσιοδότηση, συγκατάθεση, επικύρωση εισόδων εργαλείων και έλεγχο ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Πρωτόκολλο AI Agent-to-Agent (A2A)

Το A2A επιτρέπει στους agents να εντοπίζουν ο ένας τον άλλο μέσω μιας κάρτας agent και να ανταλλάσσουν εργασίες μέσω HTTP. Ελέγξτε τις κάρτες agent, την εξουσιοδότηση εργασιών, τα webhooks ειδοποιήσεων push και τις εκτεταμένες κάρτες:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Εκτεθειμένες AI υπηρεσίες που φιλοξενούνται αυτοδύναμα

Αποτυπώστε τα χαρακτηριστικά και ελέγξτε εκτεθειμένα model runners, agent builders, ML demo UIs, compute clusters και vector databases που λειτουργούν χωρίς authentication:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing με τη βοήθεια AI και αυτοματοποιημένος εντοπισμός ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Έλεγχος πηγαίου κώδικα και επικύρωση ευπαθειών με τη βοήθεια AI

Για έλεγχο source/sink, taskflows σημείων εισόδου σε mobile, ελέγχους μοτίβων kernel και επικύρωση με βάση τεκμήρια:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering με τη βοήθεια AI

[Μερική ανύψωση κώδικα, ανίχνευση invariant MBA, αποκωδικοποίηση εξαρτώμενη από το περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots AI pentesting web black-box

Οι agents με LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών web pentesting black-box, όταν υποστηρίζονται από παρατηρησιμότητα, orchestration, χειρισμό authenticated sessions και adversarial επικύρωση:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 Ασφάλειας Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Πλαίσιο Ασφαλούς AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
