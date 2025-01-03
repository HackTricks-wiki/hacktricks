# Wye Bronkode Soektog

{{#include ../../banners/hacktricks-training.md}}

Die doel van hierdie bladsy is om **platforms te noem wat toelaat om kode** (letterlik of regex) in duisende/miljoene repos op een of meer platforms te soek.

Dit help in verskeie gevalle om **gelekte inligting** of **kwesbaarhede** patrone te soek.

- [**SourceGraph**](https://sourcegraph.com/search): Soek in miljoene repos. Daar is 'n gratis weergawe en 'n ondernemingsweergawe (met 15 dae gratis). Dit ondersteun regexes.
- [**Github Search**](https://github.com/search): Soek oor Github. Dit ondersteun regexes.
- Miskien is dit ook nuttig om ook [**Github Code Search**](https://cs.github.com/) te kyk.
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Soek oor Gitlab projekte. Ondersteun regexes.
- [**SearchCode**](https://searchcode.com/): Soek kode in miljoene projekte.

> [!WARNING]
> Wanneer jy soek na lekkasies in 'n repo en iets soos `git log -p` uitvoer, moenie vergeet dat daar dalk **ander takke met ander verbintenisse** is wat geheime bevat nie!

{{#include ../../banners/hacktricks-training.md}}
