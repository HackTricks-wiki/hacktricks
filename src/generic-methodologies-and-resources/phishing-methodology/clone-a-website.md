# Kloniranje veb-sajta

Za phishing procenu ponekad može biti korisno potpuno **klonirati/izdumpovati veb-sajt**.

Imajte na umu da kloniranom veb-sajtu možete dodati i neke payload-e, kao što je BeEF hook, kako biste „kontrolisali“ korisnikov tab.

U tu svrhu možete koristiti različite alate:

## wget

Sledeća komanda koristi Wget-ove režime za mirroring, page-requisite, link-conversion i extension-adjustment, a zatim poslužuje preuzete fajlove iz trenutnog direktorijuma pomoću Python-ovog `http.server` modula na portu 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository opisuje ovaj alat kao alat za preuzimanje website-a u lokalni direktorijum uz očuvanje strukture relativnih linkova i dokumentuje korišćenje naredbe `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Alat za socijalni inženjering

Repozitorijum Social-Engineer Toolkit (SET) navodi SET kao open-source penetration-testing framework za ovlašćene procene socijalnog inženjeringa.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget priručnik](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` dokumentacija](https://docs.python.org/3/library/http.server.html)
- [3] [goclone repozitorijum](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit repozitorijum](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
