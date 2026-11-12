# GitHub Issues en repository-lêers as ’n C2-kanaal

{{#include ../banners/hacktricks-training.md}}

’n Private repository kan **sessietoestand** van **payload-oordrag** skei: issues teken elke host en sy handshake-toestand aan, terwyl repository-lêers geïnkripteerde data in albei rigtings dra. Dit behels meer as om bloot ’n issue-liggaam vir opdragte te poll. Die waargenome implementering gebruik ’n GitHub personal access token (PAT) om toegang tot albei API’s te kry.<sup>[[1]](#references)</sup> Vir ’n fynkorrelige PAT vereis die skep of bywerk van issues Issues write permission, en die oplaai van lêers vereis Contents write permission. ’n Klassieke PAT vereis eerder die `repo`-scope. Enigiemand wat ’n token met voldoende voorregte bekom, kan toegang tot dieselfde kanaal kry.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue- en lêer-handshake

Een waargenome werkvloei gebruik ’n kort heksadesimale host-ID en die volgende toestandsmasjien. Die presiese ID-reeks, stringe en voorvoegsels is protokolmerkers, nie GitHub API-vereistes nie.<sup>[[1]](#references)</sup>

1. Soek by opstart na vorige sessietoestand in oop en geslote issues met `GET /repos/{owner}/{repo}/issues?state=open` (en `state=closed`). Skep ’n oop issue met die titel `1[ID]` en die liggaam `hel` deur `POST /repos/{owner}/{repo}/issues` te gebruik.
2. Lees ’n repository-lêer waarvan die naam met `2[ID]` begin; dit verskaf die bediener se RSA-public key. Genereer ’n nuwe 16-greep-sessiesleutel, enkripteer dit met RSA en laai die resultaat op in ’n lêer met die voorvoegsel `1[ID]`.
3. Lei die daaropvolgende IV af deur die ingebedde IV met daardie sessiesleutel te XOR. Gebruik vir elke lêer wat uitgeruil word die ewekansige 16-greep-sleutel in die lêernaam om die inhoud met AES te enkripteer of dekripteer. Voorvoegsel `2` dui data van bediener na host aan; voorvoegsel `1` dui data van host na bediener aan. Die lêernaam dra dus roetering- en sleutelmateriaal per lêer, terwyl die issue die toestand dra.
4. Lees die volgende lêer met die voorvoegsel `2` en vereis dat die gedekripteerde inhoud gelyk is aan `hel`. Laai geïnkripteerde host-inligting op en verander dan die issue-liggaam na `hey` met `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Begin eers daarna om opdragte te poll.

GitHub se Contents API lees ’n lêer met `GET /repos/{owner}/{repo}/contents/{path}` en skep of vervang een met `PUT` by daardie pad. Vir lêers van hoogstens 1 MB sluit die verstek-JSON-antwoord Base64-geënkodeerde inhoud in; lêers tussen 1 en 100 MB vereis die raw media type om hul inhoud te kry. Die oplaaiversoekliggaam benodig ’n commit-boodskap en Base64-geënkodeerde lêerinhoud; wanneer ’n bestaande lêer vervang word, is sy huidige blob-SHA ook nodig. Hierdie API-besonderhede staan los van die enkripsieprotokol hier bo.<sup>[[2]](#references)[[3]](#references)</sup>

Vir ’n gemagtigde toetsrepository kan die issue-beheergedeelte met die REST API getoets word (vervang dit met ’n toetsrepository en toets-PAT). Moenie ’n aktiewe token in die URL, issue-liggaam of ’n toegewyde lêer plaas nie.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Die meganisme vereis **nie** die issue-titel, `hel`-/`hey`-merkers of die spesifieke keuses van syfersleutels wat hier gewys word nie; dit dui op een implementering. Die herbruikbare idee is om veranderlike gasheertoestand van tweerigting-geënkripteerde voorwerpe te skei en albei aan ’n gasheer-ID te koppel.<sup>[[1]](#references)</sup> Vir nog ’n GitHub-issue-vervoermetode, sien die [AdaptixC2-aantekeninge oor pasgemaakte luisteraars](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Vir ’n terugvalopsie met issue-kommentaar wat bewaarplekbewyse roteer eerder as om sessietoestand te dra, sien [Webdienste en dead-drop-oplossers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operasie FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – REST API-eindpunte vir issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – REST API-eindpunte vir bewaarplekinhoud](https://docs.github.com/en/rest/repos/contents)
