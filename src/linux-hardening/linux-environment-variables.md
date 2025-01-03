# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Vigezo vya ulimwengu **vitakuwa** vinarithiwa na **mchakato wa watoto**.

Unaweza kuunda kigezo cha ulimwengu kwa ajili ya kikao chako cha sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Kigezo hiki kitapatikana na vikao vyako vya sasa na michakato yake ya watoto.

Unaweza **kuondoa** kigezo kwa kufanya:
```bash
unset MYGLOBAL
```
## Local variables

Mabadiliko ya **local** yanaweza tu **kupatikana** na **shell/script** ya **sasa**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodha ya mabadiliko ya sasa
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – onyesho linalotumiwa na **X**. Kigezo hiki kawaida huwekwa kwenye **:0.0**, ambayo inamaanisha onyesho la kwanza kwenye kompyuta ya sasa.
- **EDITOR** – mhariri wa maandiko anayependelea mtumiaji.
- **HISTFILESIZE** – idadi ya juu ya mistari iliyomo kwenye faili ya historia.
- **HISTSIZE** – Idadi ya mistari iliyoongezwa kwenye faili ya historia wakati mtumiaji anamaliza kikao chake.
- **HOME** – saraka yako ya nyumbani.
- **HOSTNAME** – jina la mwenyeji wa kompyuta.
- **LANG** – lugha yako ya sasa.
- **MAIL** – eneo la spuli ya barua ya mtumiaji. Kawaida **/var/spool/mail/USER**.
- **MANPATH** – orodha ya saraka za kutafuta kurasa za mwongozo.
- **OSTYPE** – aina ya mfumo wa uendeshaji.
- **PS1** – kiashiria cha chaguo-msingi katika bash.
- **PATH** – huhifadhi njia ya saraka zote ambazo zina faili za binary unazotaka kutekeleza kwa kutaja tu jina la faili na si kwa njia ya uhusiano au ya moja kwa moja.
- **PWD** – saraka ya kazi ya sasa.
- **SHELL** – njia ya shell ya amri ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – eneo lako la muda.
- **USER** – jina lako la mtumiaji wa sasa.

## Interesting variables for hacking

### **HISTFILESIZE**

Badilisha **thamani ya kigezo hiki kuwa 0**, ili wakati unapo **maliza kikao chako** faili ya **historia** (\~/.bash_history) **itafutwa**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya hii variable kuwa 0**, ili wakati unapo **maliza kikao chako** amri yoyote itaongezwa kwenye **faili ya historia** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Mchakato utautumia **proxy** iliyotangazwa hapa kuungana na mtandao kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Mchakato utaamini vyeti vilivyoonyeshwa katika **hizi env variables**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Badilisha jinsi ya kuonekana kwa kiashiria chako.

[**Hii ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Mtu mzima:

![](<../images/image (897).png>)

Mtumiaji wa kawaida:

![](<../images/image (740).png>)

Kazi tatu zilizopangwa nyuma:

![](<../images/image (145).png>)

Kazi moja iliyopangwa nyuma, moja ilisimamishwa na amri ya mwisho haikukamilika vizuri:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
