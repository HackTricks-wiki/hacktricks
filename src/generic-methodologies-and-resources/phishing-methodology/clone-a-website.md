# Ku-clone Website

Kwa tathmini ya phishing, wakati mwingine inaweza kuwa muhimu **ku-clone/kudump website** kabisa.

Kumbuka kwamba unaweza pia kuongeza payloads kwenye website iliyoclonewa, kama vile BeEF hook ya "kudhibiti" tab ya mtumiaji.

Kuna tools tofauti unazoweza kutumia kwa madhumuni haya:

## wget

Command ifuatayo hutumia modes za Wget za mirroring, page-requisite, link-conversion, na extension-adjustment, kisha inahudumia files zilizopakuliwa kutoka kwenye directory ya sasa kwa kutumia module ya Python ya `http.server` kwenye port 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Hifadhi ya goclone inaeleza utility hiyo kuwa inapakua website kwenye directory ya ndani huku ikihifadhi muundo wake wa relative links, na inaandika matumizi ya amri ya `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolit

Repository ya Social-Engineer Toolkit (SET) inaitambua SET kama framework ya open-source ya pentesting kwa ajili ya assessments zilizoidhinishwa za social engineering.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Mwongozo wa GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Nyaraka za Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Hazina ya goclone](https://github.com/imthaghost/goclone)
- [4] [Hazina ya Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
