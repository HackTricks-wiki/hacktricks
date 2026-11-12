# GitHub Issues na Faili za Repository kama Channel ya C2

{{#include ../banners/hacktricks-training.md}}

Repository ya faragha inaweza kutenganisha **hali ya session** na **uhamishaji wa payload**: issues huhifadhi taarifa za kila host na hali yake ya handshake, huku faili za repository zikibeba data iliyosimbwa kwa njia fiche katika pande zote mbili. Hii ni zaidi ya kuulizia tu issue body ili kupata amri. Utekelezaji ulioonekana hutumia GitHub personal access token (PAT) kufikia API zote mbili.<sup>[[1]](#references)</sup> Kwa PAT yenye ruhusa maalum, kuunda au kusasisha issues kunahitaji ruhusa ya Issues write, na kupakia faili kunahitaji ruhusa ya Contents write. PAT ya kawaida badala yake inahitaji scope ya `repo`. Mtu yeyote anayepata token yenye ruhusa za kutosha anaweza kufikia channel hiyo hiyo.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake ya issue na faili

Workflow moja iliyoonekana hutumia host ID fupi ya hexadecimal na state machine ifuatayo. Masafa halisi ya ID, mifuatano na viambishi awali ni alama za protocol, si mahitaji ya GitHub API.<sup>[[1]](#references)</sup>

1. Programu inapoanza, ulizia issues zilizo wazi na zilizofungwa kwa kutumia `GET /repos/{owner}/{repo}/issues?state=open` (na `state=closed`) ili kupata hali ya awali ya session. Unda issue iliyo wazi yenye kichwa `1[ID]` na body `hel` kwa kutumia `POST /repos/{owner}/{repo}/issues`.
2. Soma faili ya repository ambayo jina lake linaanza na `2[ID]`; ina ufunguo wa umma wa RSA wa server. Tengeneza ufunguo mpya wa session wa baiti 16, usimba kwa RSA na upakie matokeo kwenye faili yenye kiambishi awali `1[ID]`.
3. Pata IV inayofuata kwa kufanya XOR ya IV iliyojumuishwa na ufunguo huo wa session. Kwa kila faili inayobadilishana, tumia ufunguo nasibu wa baiti 16 kutoka kwenye jina la faili yake kusimba au kusimbua maudhui kwa AES. Kiambishi awali `2` huashiria data kutoka server kwenda host; kiambishi awali `1` huashiria data kutoka host kwenda server. Hivyo, jina la faili hubeba taarifa za uelekezaji na nyenzo za ufunguo wa kila faili, huku issue ikibeba hali.
4. Soma faili inayofuata yenye kiambishi awali `2` na uhakikishe kuwa maudhui yake yaliyosimbuliwa ni `hel`. Pakia taarifa zilizosimbwa za host, kisha badilisha body ya issue iwe `hey` kwa kutumia `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Anza kuulizia amri baada ya hatua hiyo tu.

GitHub Contents API husoma faili kwa kutumia `GET /repos/{owner}/{repo}/contents/{path}` na huunda au kubadilisha faili kwa kutumia `PUT` kwenye path hiyo. Kwa faili zisizozidi MB 1, jibu chaguomsingi la JSON hujumuisha maudhui yaliyosimbwa kwa Base64; faili za MB 1 hadi MB 100 zinahitaji aina ya media ghafi ili kupata maudhui yake. Mwili wa ombi la upakiaji unahitaji ujumbe wa commit na maudhui ya faili yaliyosimbwa kwa Base64; kubadilisha faili iliyopo pia kunahitaji SHA ya blob yake ya sasa. Maelezo hayo ya API ni tofauti na protocol ya usimbaji iliyoelezwa hapo juu.<sup>[[2]](#references)[[3]](#references)</sup>

Kwa repository ya majaribio iliyoidhinishwa, sehemu ya kudhibiti issue inaweza kujaribiwa kwa kutumia REST API (badilisha kwa repository ya majaribio na PAT ya majaribio). Usiweke token inayotumika kwenye URL, issue body au faili iliyocommitiwa.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Mekanizimu hii **haihitaji** issue title, alama za `hel`/`hey` au chaguo mahususi za cipher zilizoonyeshwa hapa; vitu hivyo hutambulisha implementation moja. Wazo linaloweza kutumika tena ni kutenganisha hali ya host inayobadilika na objects zilizosimbwa kwa njia fiche za mawasiliano ya pande mbili, na kuvifungamanisha vyote na host ID.<sup>[[1]](#references)</sup> Kwa usafirishaji mwingine wa GitHub issue, tazama [maelezo ya custom listener ya AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Kwa njia mbadala inayotumia maoni ya issue na inayozungusha credentials za repository badala ya kubeba hali ya session, tazama [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operesheni FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Endpoints za REST API za issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Endpoints za REST API za maudhui ya repository](https://docs.github.com/en/rest/repos/contents)
