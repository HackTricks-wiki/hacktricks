# AI u sajberbezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolja početna tačka za učenje o AI-ju jeste razumevanje načina na koji rade glavni algoritmi mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadate:


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

### Arhitektura LLM-ova

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izgradnju osnovnog LLM-a pomoću transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezbednost AI-ja

### Okviri za procenu AI rizika

Trenutno su 2 glavna okvira za procenu rizika AI sistema OWASP ML Top 10 i Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezbednost AI promptova

LLM-ovi su doveli do ogromnog porasta upotrebe AI-ja poslednjih godina, ali nisu savršeni i mogu se prevariti adversarial promptovima. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se on može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Veoma je uobičajeno da developeri i kompanije pokreću modele preuzete sa Interneta, međutim, samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se on može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je protokol koji omogućava AI agent klijentima da se povežu sa eksternim alatima i izvorima podataka na plug-and-play način. Ovo omogućava složene radne tokove i interakcije između AI modela i eksternih sistema:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester botovi

Agenti zasnovani na LLM-ovima mogu automatizovati dugotrajne black-box web pentesting radne tokove kada imaju podršku za observability, orkestraciju, upravljanje autentifikovanim sesijama i adversarial validaciju:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
