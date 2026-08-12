# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Database ya Authorization

Security framework ya Authorization Services huruhusu privileged helpers na vipengele vingine kutathmini authorization rights zenye majina. Katika matoleo ya sasa ya macOS, sheria nyingi hizo huhifadhiwa kwenye `/var/db/auth.db` na kutathminiwa na `authd`; faili hili pamoja na schema yake ya SQLite ni implementation details na zinaweza kubadilika kati ya matoleo.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

System defaults kwa kihistoria zimeanzishwa kutoka `/System/Library/Security/authorization.plist`, na installers au privileged services zinaweza kuongeza named rights. Tumia interface inayoungwa mkono ya `security authorizationdb read|write|remove` badala ya kuhariri database moja kwa moja.<sup>[[3]](#references)</sup>

Jedwali la `rules` lililoonekana kwenye build iliyoandikwa lina columns zifuatazo. Ichukulie hii kama forensic map, si public schema thabiti:

- **id**: Kitambulisho cha kipekee cha kila rule, huongezwa automatically na hutumika kama primary key.
- **name**: Jina la kipekee la rule linalotumika kuitambua na kuirejelea ndani ya authorization system.
- **type**: Hubainisha aina ya rule, ikiwa na kikomo cha values 1 au 2 ili kufafanua authorization logic yake.
- **class**: Huainisha rule katika class maalum, na lazima iwe positive integer.
- Rule classes za kawaida ni `allow`, `deny`, `user`, `rule`, na `evaluate-mechanisms`. Mechanisms zinaweza kuwa built-ins au Security Agent plug-ins zilizo chini ya `/System/Library/CoreServices/SecurityAgentPlugins/` au `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Huonyesha user group inayohusishwa na rule kwa ajili ya group-based authorization.
- **kofn**: Inawakilisha parameter ya "k-of-n", inayoamua ni subrules ngapi lazima zitimizwe kati ya jumla fulani.
- **timeout**: Hufafanua muda kwa sekunde kabla ya authorization iliyotolewa na rule ku-expire.
- **flags**: Ina flags mbalimbali zinazobadilisha tabia na sifa za rule.
- **tries**: Huweka kikomo cha idadi ya authorization attempts zinazoruhusiwa ili kuimarisha security.
- **version**: Hufuatilia version ya rule kwa ajili ya version control na updates.
- **created**: Hurekodi timestamp wakati rule iliundwa kwa madhumuni ya auditing.
- **modified**: Huhifadhi timestamp ya modification ya mwisho iliyofanywa kwenye rule.
- **hash**: Huhifadhi hash value ya rule ili kuhakikisha integrity yake na kugundua tampering.
- **identifier**: Hutoa string identifier ya kipekee, kama UUID, kwa external references za rule.
- **requirement**: Ina serialized data inayofafanua authorization requirements na mechanisms maalum za rule.
- **comment**: Hutoa maelezo au comment inayoeleweka na binadamu kuhusu rule kwa ajili ya documentation na uwazi.

### Mfano
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Kanuni iliyodekodishwa ifuatayo inaonyesha `authenticate-admin-nonshared` kwenye toleo la macOS lililoandikwa:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

`authd` ni huduma ya XPC inayotathmini maombi ya Authorization Services. Kwenye matoleo ya sasa ya macOS, bundle yake inaweza kuchunguzwa kwenye `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; path hii ni maelezo ya utekelezaji na inaweza kutofautiana kati ya matoleo. Matoleo ya zamani yaliandika kwenye `/var/log/authd.log`; matoleo ya sasa hutumia hasa unified logging system, ambayo inaweza kuulizwa kwa `log show`/`log stream` kwa kutumia process predicate ya `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Tool ya `security` hufichua operations kadhaa za Authorization Services. Mfano wa kihistoria hutumia `AuthorizationExecuteWithPrivileges` pamoja na `security execute-with-privileges /bin/ls`. Apple ilitangaza API hiyo kuwa deprecated katika macOS 10.7; privileged helpers za kisasa zinapaswa kutumia helper inayosimamiwa na launchd pamoja na XPC authorization.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Kwenye matoleo ambayo bado yana support hiyo, hii hutumia `/usr/libexec/security_authtrampoline` na kuonyesha authorization prompt kabla ya kuendesha command kama root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Muhtasari wa macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Mwongozo wa Apple wa Programming wa Authorization Services (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Ukurasa wa manual wa `security(1)` wa macOS](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Mwongozo wa Programming wa Daemons and Services: Kuunda launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Mradi wa Apple wa Security wenye source code wazi - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
