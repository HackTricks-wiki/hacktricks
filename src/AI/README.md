# AI u Kibernetičkoj Bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni Algoritmi Mašinskog Učenja

Najbolja polazna tačka za učenje o AI je razumevanje kako glavni algoritmi mašinskog učenja funkcionišu. Ovo će vam pomoći da razumete kako AI funkcioniše, kako ga koristiti i kako ga napasti:

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

Na sledećoj stranici ćete pronaći osnove svakog komponente za izgradnju osnovnog LLM koristeći transformere:

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezbednost AI

### Okviri Rizika AI

U ovom trenutku, glavna 2 okvira za procenu rizika AI sistema su OWASP ML Top 10 i Google SAIF:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezbednost AI Upita

LLM-ovi su u poslednjim godinama doveli do eksplozije korišćenja AI, ali nisu savršeni i mogu biti prevareni zlonamernim upitima. Ovo je veoma važna tema za razumevanje kako koristiti AI bezbedno i kako ga napasti:

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE Modela AI

Veoma je uobičajeno da programeri i kompanije pokreću modele preuzete sa Interneta, međutim, samo učitavanje modela može biti dovoljno da se izvrši proizvoljan kod na sistemu. Ovo je veoma važna tema za razumevanje kako koristiti AI bezbedno i kako ga napasti:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protokol Konteksta Modela AI

MCP (Protokol Konteksta Modela) je protokol koji omogućava AI agent klijentima da se povežu sa spoljnim alatima i izvorima podataka na način "plug-and-play". Ovo omogućava složene radne tokove i interakcije između AI modela i spoljnih sistema:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
