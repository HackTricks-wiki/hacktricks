# Electron Auto-Update Trust Boundaries

{{#include ../../banners/hacktricks-training.md}}

## Electron auto-update attack surface

Updater को remote-code-execution boundary मानें: यह executable content प्राप्त करता है, तय करता है कि वह content नया और trusted है या नहीं, उसे स्थानीय रूप से stage करता है और installer को सौंपता है। पूरे trust graph की समीक्षा करें—release index, per-version metadata, artifact, detached signatures, embedded verification key, cache, temporary path और installer—सिर्फ यह नहीं कि अंतिम `.app` signed है या नहीं।<sup>[[1]](#references)[[2]](#references)</sup>

### High-value tests

- **Rollback/replay:** पहले से valid manifest और उसके अब भी signed artifact को replay करें। Signature अपने input को authenticate करता है, लेकिन freshness नहीं देता; client को persistent monotonic floor से नीचे के versions अस्वीकार करने चाहिए, जब तक authenticated recovery policy स्पष्ट रूप से rollback की अनुमति न दे।<sup>[[2]](#references)</sup>
- **Metadata/artifact substitution:** version, URL, expected hash, artifact और detached signature को अलग-अलग बदलकर देखें। एक release के valid artifact/signature pair को दूसरी release के metadata के साथ मिलाकर भी आज़माएँ। यदि release metadata unsigned है, तो TLS या signed final executable, compromised origin/CDN को selection logic बदलने से नहीं रोकता।<sup>[[1]](#references)[[2]](#references)</sup>
- **Signed channel confusion:** production feed के ज़रिए वैध रूप से signed alpha, beta, development या debug build परोसें। सभी environments में एक ही key और policy का पुनः उपयोग करने पर artifact, केवल signer की जाँच में पास हो सकता है; production identity/channel को authenticated policy का हिस्सा होना चाहिए या अलग trust root का उपयोग करना चाहिए।<sup>[[2]](#references)</sup>
- **Temporary-file TOCTOU:** पता करें कि verification किसी pathname को खोलता है या नहीं और installation के दौरान बाद में उसी pathname को फिर से खोला जाता है या नहीं। यदि कोई local attacker इन operations के बीच staged object का नाम बदल सकता है, उसे बदल सकता है या redirect कर सकता है, तो installer ऐसे bytes इस्तेमाल कर सकता है जिनका कभी verification नहीं हुआ। `0700` mode वाली staging directory access को सीमित करती है, लेकिन दोनों operations को atomic नहीं बनाती।<sup>[[2]](#references)</sup>

Static और runtime triage इन boundaries को तेज़ी से ढूँढ़ने में मदद कर सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

किसी अधिकृत परीक्षण के दौरान, update check को intercept करें, हर response को archive करें और एक बार में एक field में बदलाव करें। फिर staging directory के ownership/mode की जाँच करें और download से installation तक file opens को trace करें। macOS पर, यदि flow किसी privileged helper तक पहुँचता है, तो [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) जारी रखें और [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) की समीक्षा करें—“signed” को पूर्ण identity check न मानें।<sup>[[2]](#references)</sup>

### अपेक्षित binding और policy

एक भरोसेमंद design, selection metadata और artifact bytes—दोनों को authenticate करता है। SafeUpdater reference design में embedded Ed25519 public key, signed manifests और artifacts, `SHA-256(file)` तथा version से निकला signed message, और signed metadata में रखा SHA-512 artifact digest शामिल हैं; इसे स्पष्ट रूप से एक research reference बताया गया है, production-ready package नहीं।<sup>[[1]](#references)[[2]](#references)</sup>

सत्यापित करें कि target में ये अतिरिक्त गुण भी हैं।<sup>[[1]](#references)[[2]](#references)</sup>

- ऐसा अस्पष्टता-रहित signed representation इस्तेमाल करता है, जो artifact digest को उसके canonical version और release environment से बाँधता है;
- downgrade को default रूप से disable करता है और अधिकृत rollback के लिए न्यूनतम स्वीकार्य version लागू करता है;
- अलग keys/channels या authenticated release-policy data के ज़रिए production को non-production से अलग रखता है; और
- उसी pathname को फिर से resolve करने के बजाय, पहले से verified open file (या उसके समकक्ष immutable handle/object) को install करता है।

## References

- [1] [Doyensec ElectronSafeUpdater reference implementation](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: सुरक्षित Electron Auto-Update Mechanism का design](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
