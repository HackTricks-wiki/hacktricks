# Ku-clone Website

{{#include ../../banners/hacktricks-training.md}}

Kwa tathmini ya phishing, wakati mwingine inaweza kuwa muhimu kabisa **ku-clone/dump website**.

Kumbuka kwamba unaweza pia kuongeza baadhi ya payloads kwenye website iliyoclonewa, kama vile BeEF hook ya "kudhibiti" tab ya mtumiaji.

Kuna tools tofauti unazoweza kutumia kwa madhumuni haya:

## wget

Amri ifuatayo hutumia modes za Wget za mirroring, page-requisite, link-conversion, na extension-adjustment, kisha hu-serve files zilizopakuliwa kutoka directory ya sasa kwa kutumia module ya Python ya `http.server` kwenye port 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Hifadhi ya goclone inaeleza utility hii kama inayopakua website kwenye directory ya ndani huku ikihifadhi muundo wake wa relative links, na inaandika matumizi ya amri `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Zana za Social Engineering

Hifadhi ya SET inaitambua SET kama framework ya open-source ya penetration-testing kwa ajili ya tathmini zilizoidhinishwa za Social Engineering.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Mwongozo wa GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Nyaraka za Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Hifadhi ya goclone](https://github.com/imthaghost/goclone)
- [4] [Hifadhi ya Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
