# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι αλγόριθμοι Machine Learning

Το καλύτερο σημείο εκκίνησης για να μάθετε για το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

Για διαχωρισμούς dataset, κλασικές μετρικές και επιθέσεις στην πλευρά των απαντήσεων κατά της βαθμολόγησης με βάση LLM, δείτε την [προετοιμασία και αξιολόγηση δεδομένων μοντέλων](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Αρχιτεκτονική LLM

Στην παρακάτω σελίδα θα βρείτε τα βασικά στοιχεία κάθε συστατικού για τη δημιουργία ενός βασικού LLM με χρήση transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για εκτέλεση, fine-tuning, παροχή ή δοκιμή μοντέλων, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

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

Δύο χρήσιμα πλαίσια για την αξιολόγηση του κινδύνου συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητική λίστα πλαισίων κινδύνου AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarial επιθέσεις με καθοδήγηση από mechanistic interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Όρια εμπιστοσύνης ενσωματωμένων browser στο AI

Για browser bridges desktop assistants, πλαστογράφηση διευθύνσεων καρτελών και αναγνώσεις τοπικών αρχείων από worker context, δείτε τα [όρια εμπιστοσύνης ενσωματωμένων browser του AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Ασφάλεια prompts AI

Τα LLM έχουν οδηγήσει σε εκρηκτική αύξηση της χρήσης AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε AI Models

Είναι πολύ συνηθισμένο για developers και εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Παράκαμψη KYC με υποβοήθηση AI

Η παραγωγή video μπορεί να συνδυαστεί με έγχυση virtual camera και χειρισμό camera API για την παράκαμψη αδύναμων διαδικασιών KYC, επαλήθευσης ηλικίας και βιομετρικού ελέγχου ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν εξουσιοδότηση, συγκατάθεση, επικύρωση εισόδων εργαλείων και ανασκόπηση ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Πρωτόκολλο AI Agent-to-Agent (A2A)

Το A2A επιτρέπει στους agents να ανακαλύπτουν ο ένας τον άλλον μέσω μιας agent card και να ανταλλάσσουν εργασίες μέσω HTTP. Δοκιμάστε τις agent cards, την εξουσιοδότηση εργασιών, τα push-notification webhooks και τις extended cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Εκτεθειμένες self-hosted υπηρεσίες AI

Fingerprinting και δοκιμή εκτεθειμένων model runners, agent builders, ML demo UI, compute clusters και vector databases που λειτουργούν χωρίς authentication:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing με υποβοήθηση AI και αυτοματοποιημένη ανακάλυψη ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ανασκόπηση πηγαίου κώδικα και επικύρωση ευπαθειών με υποβοήθηση AI

Για ανασκόπηση source/sink, mobile entry-point taskflows, ελέγχους μοτίβων kernel και επικύρωση με βάση τεκμήρια:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering με υποβοήθηση AI

[Partial lifting, ανίχνευση invariant MBA, αποκωδικοποίηση δεσμευμένη σε περιβάλλον και επικύρωση automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Οι agents με LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών black-box web pentesting όταν υποστηρίζονται από observability, orchestration, χειρισμό authenticated sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — Οι 10 κορυφαίες απειλές ασφάλειας Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Ασφαλές AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
