# AI u sajber-bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolje je da učenje o AI-ju počnete tako što ćete razumeti kako funkcionišu glavni algoritmi mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

### Priprema i evaluacija podataka modela

Za podelu skupova podataka, klasične metrike i napade na strani odgovora pri ocenjivanju zasnovanom na LLM-ovima pogledajte [pripremu i evaluaciju podataka modela](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arhitektura LLM-ova

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izradu osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Alati i platforme za modele

Za pokretanje, fino podešavanje, posluživanje ili isprobavanje modela koristite [vodič za AI alate i platforme za modele](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Granice poverenja LLM gateway-a

Za bezbednost gateway-a pogledajte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologija bezbednosti AI agenata

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Okviri za procenu AI rizika

Dva korisna početna okvira za procenu rizika AI sistema jesu OWASP Machine Learning Security Top 10 i Google Secure AI Framework (SAIF). Oni se dopunjuju i ne predstavljaju iscrpan spisak okvira za procenu AI rizika.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adverzarijalni napadi vođeni mehanističkom interpretabilnošću

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Granice poverenja ugrađenog pregledača

Za mostove pregledača desktop asistenata, lažiranje adresa kartica i čitanje lokalnih datoteka iz konteksta radnika pogledajte [granice poverenja ugrađenog pregledača AI asistenta](AI-Embedded-Browser-Trust-Boundaries.md).

### Bezbednost AI promptova

LLM-ovi su poslednjih godina doveli do naglog porasta upotrebe AI-ja, ali nisu savršeni i mogu se prevariti adverzarijalnim promptovima. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Programeri i kompanije veoma često pokreću modele preuzete sa Interneta, ali samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Za rizike učitavanja Keras `.keras`/HDF5 modela, Lambda slojeve i analizu gadgeta nakon ispravke pogledajte [deserijalizaciju Keras modela i pronalaženje gadgeta](keras-model-deserialization-rce-and-gadget-hunting.md).

### Zaobilaženje KYC-a uz pomoć AI-ja

Generativni video može se kombinovati sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere kako bi se zaobišli slabi KYC postupci, provere uzrasta i provere biometrijske živosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol za AI

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju obuhvatiti autorizaciju, saglasnost, validaciju ulaza u alate i pregled granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### A2A protokol za komunikaciju AI agenata

A2A omogućava agentima da otkrivaju jedni druge putem agentske kartice i da međusobno šalju zadatke preko HTTP-a. Testirajte agentske kartice, autorizaciju zadataka, webhook-ove za push obaveštenja i proširene kartice:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Izložene samostalno hostovane AI usluge

Otkrivanje otiska i testiranje izloženih pokretača modela, alata za izradu agenata, ML demo interfejsa, računarskih klastera i vektorskih baza podataka koji rade bez autentifikacije:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i validacija ranjivosti uz pomoć AI-ja

Za pregled izvora i odredišta podataka, tokove zadataka mobilnih ulaznih tačaka, provere obrazaca u kernelu i validaciju zasnovanu na dokazima:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverzno inženjerstvo uz pomoć AI-ja

[Delimično podizanje nivoa apstrakcije, otkrivanje invarijantnih MBA izraza, dekodiranje vezano za okruženje i validacija automatizovanih ekstraktora](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web black-box pentester botovi sa AI-jem

Agenti zasnovani na LLM-ovima mogu da automatizuju dugotrajne black-box web pentesting tokove rada kada imaju podršku opservabilnosti, orkestracije, obrade autentifikovanih sesija i adverzarijalne validacije:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 za bezbednost mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Okvir za bezbedan AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
