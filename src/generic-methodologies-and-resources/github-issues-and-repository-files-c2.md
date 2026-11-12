# C2 चैनल के रूप में GitHub Issues और Repository Files

{{#include ../banners/hacktricks-training.md}}

एक private repository **session state** को **payload transfer** से अलग रख सकती है: issues प्रत्येक host और उसकी handshake state दर्ज करते हैं, जबकि repository files दोनों दिशाओं में encrypted data ले जाती हैं। यह केवल commands के लिए issue body को बार-बार जाँचने से कहीं अधिक है। देखे गए implementation में दोनों APIs तक पहुँचने के लिए GitHub personal access token (PAT) का उपयोग होता है।<sup>[[1]](#references)</sup> Fine-grained PAT के लिए issues बनाने या अपडेट करने हेतु Issues write permission और files upload करने हेतु Contents write permission चाहिए। इसके बजाय classic PAT को `repo` scope चाहिए। पर्याप्त permissions वाला token पाने वाला कोई भी व्यक्ति उसी चैनल तक पहुँच सकता है।<sup>[[2]](#references)[[3]](#references)</sup>

## Issue और file handshake

देखे गए एक workflow में छोटा hexadecimal host ID और निम्न state machine उपयोग होती है। ID की सटीक range, strings और prefixes protocol markers हैं, GitHub API की आवश्यकताएँ नहीं।<sup>[[1]](#references)</sup>

1. Startup पर, पिछली session state खोजने के लिए `GET /repos/{owner}/{repo}/issues?state=open` (और `state=closed`) से open और closed issues query करें। `POST /repos/{owner}/{repo}/issues` का उपयोग करके `hel` body वाला `1[ID]` शीर्षक का open issue बनाएँ।
2. ऐसी repository file पढ़ें जिसका नाम `2[ID]` से शुरू होता हो; इसमें server की RSA public key होती है। एक नई 16-byte session key बनाएँ, उसे RSA से encrypt करें और परिणाम को `1[ID]` prefix वाली file में upload करें।
3. अगली IV को embedded IV और उस session key का XOR करके derive करें। हर exchanged file के लिए, उसकी filename में मौजूद random 16-byte key का उपयोग contents को AES से encrypt या decrypt करने के लिए करें। Prefix `2` server-to-host data दर्शाता है; prefix `1` host-to-server data दर्शाता है। इस तरह filename में routing और प्रति-file key material होता है, जबकि issue state रखता है।
4. अगली `2`-prefix वाली file पढ़ें और सुनिश्चित करें कि उसका decrypted content `hel` के बराबर हो। Encrypted host information upload करें, फिर `PATCH /repos/{owner}/{repo}/issues/{issue_number}` के साथ issue body को `hey` में बदलें। इसके बाद ही command polling शुरू करें।

GitHub का Contents API, `GET /repos/{owner}/{repo}/contents/{path}` के ज़रिए file पढ़ता है और उस path पर `PUT` के ज़रिए file बनाता या बदलता है। अधिकतम 1 MB की files के लिए, default JSON response में Base64-encoded content शामिल होता है; 1 से 100 MB के बीच की files का content पाने के लिए raw media type चाहिए। Upload body में commit message और Base64-encoded file contents होने चाहिए; मौजूदा file को बदलने के लिए उसका वर्तमान blob SHA भी चाहिए। ये API विवरण ऊपर दिए encryption protocol से अलग हैं।<sup>[[2]](#references)[[3]](#references)</sup>

किसी authorized test repository के लिए, REST API से issue-control वाले हिस्से को जाँचा जा सकता है (एक test repository और test PAT का उपयोग करें)। किसी live token को URL, issue body या committed file में न रखें।<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

यह mechanism यहाँ दिखाए गए issue title, `hel`/`hey` markers या खास cipher choices पर निर्भर **नहीं** करता; ये केवल एक implementation की पहचान बताते हैं। दोबारा इस्तेमाल किया जा सकने वाला विचार है mutable host state को bidirectional encrypted objects से अलग करना और दोनों को host ID से bind करना।<sup>[[1]](#references)</sup> GitHub issue के दूसरे transport के लिए, [AdaptixC2 custom listener notes](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema) देखें। Session state ले जाने के बजाय repository credentials को rotate करने वाले issue-comment fallback के लिए, [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers) देखें।

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – issues के लिए REST API endpoints](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – repository contents के लिए REST API endpoints](https://docs.github.com/en/rest/repos/contents)
