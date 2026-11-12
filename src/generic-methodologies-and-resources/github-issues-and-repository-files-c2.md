# GitHub Issues i datoteke repozitorijuma kao C2 kanal

{{#include ../banners/hacktricks-training.md}}

Privatni repozitorijum može da razdvoji **stanje sesije** od **prenosa payload-a**: issue-i beleže svaki host i stanje njegovog handshake-a, dok datoteke u repozitorijumu prenose šifrovane podatke u oba smera. Ovo je više od pukog proveravanja tela issue-a u potrazi za komandama. U posmatranoj implementaciji koristi se GitHub personal access token (PAT) za pristup oba API-ja.<sup>[[1]](#references)</sup> Za fine-grained PAT, kreiranje ili ažuriranje issue-a zahteva dozvolu Issues write, a otpremanje datoteka zahteva dozvolu Contents write. Classic PAT umesto toga zahteva opseg `repo`. Svako ko dođe do tokena sa dovoljnim privilegijama može da pristupi istom kanalu.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue i file handshake

U jednom posmatranom toku rada koristi se kratak heksadecimalni ID hosta i sledeća mašina stanja. Tačan opseg ID-jeva, stringovi i prefiksi predstavljaju oznake protokola, a ne zahteve GitHub API-ja.<sup>[[1]](#references)</sup>

1. Pri pokretanju, pretražite otvorene i zatvorene issue-e pomoću `GET /repos/{owner}/{repo}/issues?state=open` (i `state=closed`) da biste pronašli prethodno stanje sesije. Kreirajte otvoren issue pod naslovom `1[ID]` sa telom `hel` pomoću `POST /repos/{owner}/{repo}/issues`.
2. Pročitajte datoteku u repozitorijumu čije ime počinje sa `2[ID]`; ona sadrži RSA javni ključ servera. Generišite svež 16-bajtni ključ sesije, šifrujte ga RSA-om i otpremite rezultat u datoteci sa prefiksom `1[ID]`.
3. Izvedite naredni IV tako što ćete izvršiti XOR između ugrađenog IV-a i tog ključa sesije. Za svaku razmenjenu datoteku koristite nasumični 16-bajtni ključ iz njenog imena da biste AES-om šifrovali ili dešifrovali sadržaj. Prefiks `2` označava podatke od servera ka hostu; prefiks `1` označava podatke od hosta ka serveru. Dakle, ime datoteke sadrži informacije za rutiranje i materijal ključa za svaku datoteku, dok issue sadrži stanje.
4. Pročitajte sledeću datoteku sa prefiksom `2` i proverite da li je njen dešifrovani sadržaj jednak `hel`. Otpremite šifrovane informacije o hostu, a zatim promenite telo issue-a u `hey` pomoću `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Tek tada počnite sa proveravanjem komandi.

GitHub Contents API čita datoteku pomoću `GET /repos/{owner}/{repo}/contents/{path}`, a kreira ili zamenjuje datoteku pomoću `PUT` na toj putanji. Za datoteke veličine do 1 MB, podrazumevani JSON odgovor uključuje Base64-kodirani sadržaj; za datoteke veličine od 1 do 100 MB potreban je raw media type da bi se preuzeo njihov sadržaj. Telo zahteva za otpremanje mora da sadrži commit poruku i Base64-kodirani sadržaj datoteke; za zamenu postojeće datoteke potreban je i njen trenutni blob SHA. Ti detalji API-ja razlikuju se od protokola šifrovanja opisanog iznad.<sup>[[2]](#references)[[3]](#references)</sup>

U ovlašćenom testnom repozitorijumu, deo za kontrolu issue-a može se testirati pomoću REST API-ja (zamenite testnim repozitorijumom i testnim PAT-om). Ne stavljajte aktivni token u URL, telo issue-a ili datoteku u commit-u.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Mehanizam **ne** zahteva naslov issue-a, markere `hel`/`hey` niti konkretne izbore šifara prikazane ovde; oni identifikuju jednu implementaciju. Ideja koja se može ponovo koristiti jeste da se promenljivo stanje hosta razdvoji od dvosmerno šifrovanih objekata i da se oboje povežu sa ID-jem hosta.<sup>[[1]](#references)</sup> Za drugi GitHub-issue transport pogledajte [beleške o prilagođenom listener-u AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Za rezervnu opciju koja koristi komentare na issue-u i rotira akreditive repozitorijuma umesto da prenosi stanje sesije, pogledajte [Veb servisi i dead-drop razrešivači](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operacija FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – REST API krajnje tačke za issue-e](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – REST API krajnje tačke za sadržaj repozitorijuma](https://docs.github.com/en/rest/repos/contents)
