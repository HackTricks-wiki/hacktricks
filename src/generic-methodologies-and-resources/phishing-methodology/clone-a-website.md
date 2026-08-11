# Clonazione di un sito web

{{#include ../../banners/hacktricks-training.md}}

Per una valutazione di phishing, a volte può essere utile **clonare/effettuare il dump di un sito web**.

Tieni presente che puoi anche aggiungere alcuni payload al sito web clonato, come un hook BeEF, per "controllare" la scheda dell'utente.

Esistono diversi tool che puoi utilizzare a questo scopo:

## wget

Il comando seguente utilizza le modalità di mirroring, inclusione dei requisiti della pagina, conversione dei link e modifica delle estensioni di Wget, quindi serve i file scaricati dalla directory corrente con il modulo `http.server` di Python sulla porta 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Il repository goclone descrive l'utility come uno strumento che scarica un sito web in una directory locale preservandone la struttura dei link relativi e documenta l'invocazione `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit di Social Engineering

Il repository Social-Engineer Toolkit (SET) identifica SET come un framework open-source per il penetration testing destinato alle valutazioni autorizzate di social engineering.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Manuale GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Documentazione Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Repository goclone](https://github.com/imthaghost/goclone)
- [4] [Repository Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
