# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Αλγόριθμοι Machine Learning

Το καλύτερο σημείο εκκίνησης για να μάθετε σχετικά με το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

### Αρχιτεκτονική των LLMs

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε component για τη δημιουργία ενός βασικού LLM με χρήση transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ασφάλεια AI

### Frameworks Αξιολόγησης Κινδύνων AI

Αυτή τη στιγμή, τα 2 κύρια frameworks για την αξιολόγηση των κινδύνων των AI systems είναι το OWASP ML Top 10 και το Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ασφάλεια Prompts AI

Τα LLMs έχουν προκαλέσει έκρηξη στη χρήση του AI τα τελευταία χρόνια, όμως δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε AI Models

Είναι πολύ συνηθισμένο οι developers και οι εταιρείες να εκτελούν models που έχουν κατεβάσει από το Internet. Ωστόσο, μόνο η φόρτωση ενός model μπορεί να είναι αρκετή για την εκτέλεση arbitrary code στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass με Υποβοήθηση AI

Το Generative video μπορεί να συνδυαστεί με virtual-camera injection και camera API manipulation για την παράκαμψη αδύναμων ροών KYC, επαλήθευσης ηλικίας και biometric liveness:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

Το MCP (Model Context Protocol) είναι ένα protocol που επιτρέπει σε AI agent clients να συνδέονται με external tools και data sources με plug-and-play τρόπο. Αυτό επιτρέπει σύνθετα workflows και interactions μεταξύ AI models και external systems:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

Οι agents με LLM μπορούν να αυτοματοποιούν long-running black-box web pentesting workflows όταν υποστηρίζονται από observability, orchestration, authenticated session handling και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
