# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, diamond ticket は **任意のユーザーとして任意のサービスにアクセスするために使用できる TGT** です。golden ticket は完全に offline で偽造され、そのドメインの krbtgt hash で暗号化された後、使用するために logon session へ渡されます。domain controller は自身が正当に発行した TGT を追跡しないため、自身の krbtgt hash で暗号化された TGT を問題なく受け入れます。<sup>[[1]](#references)</sup>

golden ticket の使用を検出する一般的な手法は2つあります。

- 対応する AS-REQ が存在しない TGS-REQ を探す。
- Mimikatz のデフォルトの10年 lifetime のような、不自然な値を持つ TGT を探す。

**diamond ticket** は、**DC によって発行された正規の TGT のフィールドを変更する**ことで作成されます。これは、**TGT を要求**し、ドメインの krbtgt hash で **復号**し、ticket の目的のフィールドを **変更**した後、**再暗号化する**ことで実現します。これにより、golden ticket にある **前述の2つの欠点を克服**できます。<sup>[[1]](#references)</sup>

- TGS-REQ の前に AS-REQ が存在する。
- TGT は DC によって発行されるため、ドメインの Kerberos policy に基づく正しい詳細情報がすべて含まれる。これらを golden ticket で正確に偽造することも可能ですが、より複雑で、ミスが発生しやすくなります。

### Requirements & workflow

- **Cryptographic material**: TGT を復号して再署名するための krbtgt AES256 key（推奨）または NTLM hash。
- **Legitimate TGT blob**: `/tgtdeleg`、`asktgt`、`s4u`、または memory から ticket を export して取得したもの。
- **Context data**: target user RID、group RID/SID、および（任意で）LDAP から取得した PAC attributes。
- **Service keys**（service ticket を再発行する場合のみ）: impersonate 対象の service SPN の AES key。

1. AS-REQ を使用して、制御下にある任意の user の TGT を取得する（Rubeus の `/tgtdeleg` は、credentials なしで client に Kerberos GSS-API dance を実行させるため便利）。
2. 返された TGT を krbtgt key で復号し、PAC attributes（user、groups、logon info、SIDs、device claims など）を patch する。
3. 同じ krbtgt key で ticket を再暗号化・再署名し、現在の logon session に inject する（`kerberos::ptt`、`Rubeus.exe ptt`...）。
4. 必要に応じて、有効な TGT blob と target service key を指定し、service ticket に対してこの処理を繰り返すことで、wire 上で stealthy な状態を維持する。

### Updated Rubeus tradecraft (2024+)

Huntress による最近の研究では、以前は golden/silver ticket にのみ存在していた `/ldap` と `/opsec` の改良を移植することで、Rubeus 内部の `diamond` action が modernize されました。`/ldap` は現在、LDAP に query を実行し、さらに SYSVOL を mount して account/group attributes と Kerberos/password policy（`GptTmpl.inf` など）を抽出することで、実際の PAC context を取得します。一方、`/opsec` は2段階の preauth exchange を実行し、AES-only と現実的な KDCOptions を適用することで、AS-REQ/AS-REP flow を Windows に合わせます。これにより、PAC fields の欠落や policy と一致しない lifetime など、明らかな indicators が大幅に減少します。<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap`（オプションの `/ldapuser` と `/ldappassword` を指定可能）は AD と SYSVOL をクエリし、対象ユーザーの PAC ポリシーデータをミラーリングします。
- `/opsec` は Windows に似た AS-REQ の再試行を強制し、ノイズの多いフラグをゼロにして AES256 のみに固定します。
- `/tgtdeleg` は、復号可能な TGT を返しながら、被害者のクリアテキストパスワードや NTLM/AES key に触れないようにします。

### サービスチケットの再加工

同じ Rubeus の更新で、diamond technique を TGS blob に適用できるようになりました。`diamond` に **base64-encoded TGT**（`asktgt`、`/tgtdeleg`、または以前に forged された TGT から取得）、**service SPN**、および **service AES key** を渡すことで、KDC に触れることなくリアルな service ticket を mint できます。実質的には、よりステルス性の高い silver ticket です。<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
このワークフローは、すでにサービスアカウントの key（`lsadump::lsa /inject` または `secretsdump.py` で dump したものなど）を制御しており、新しい AS/TGS トラフィックを発生させずに、AD のポリシー、タイムライン、PAC データに完全に一致する one-off TGS を発行したい場合に最適です。<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

**sapphire ticket** と呼ばれることもある新しい手法では、Diamond の「real TGT」をベースに、**S4U2self+U2U** を組み合わせて privileged PAC を窃取し、自分の TGT に組み込みます。追加の SID を作成する代わりに、`sname` が low-priv requester を対象とするように、high-privilege user に対する U2U S4U2self ticket を要求します。このとき KRB_TGS_REQ は requester の TGT を `additional-tickets` に含め、`ENC-TKT-IN-SKEY` を設定するため、service ticket をその user の key で復号できます。その後、privileged PAC を抽出し、krbtgt key で再署名する前に、正規の TGT へ splice します。<sup>[[2]](#references)[[5]](#references)</sup>

Impacket の `ticketer.py` は現在、`-impersonate` + `-request` による sapphire support（live KDC exchange）を提供しています。<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` はユーザー名または SID を受け付けます。`-request` では、チケットを復号・patchするために、実在するユーザーの creds と krbtgt key material（AES/NTLM）が必要です。

この variant を使用する際の主な OPSEC 上の兆候:<sup>[[5]](#references)</sup>

- TGS-REQ には `ENC-TKT-IN-SKEY` と `additional-tickets`（victim TGT）が含まれます。これは通常のトラフィックでは珍しいものです。
- `sname` は requesting user と同じになることが多く（self-service access）、Event ID 4769 では caller と target が同じ SPN/user として表示されます。
- 同じ client computer で、異なる CNAME（low-priv requester と privileged PAC owner）を持つ 4768/4769 エントリのペアが記録されることを想定してください。

### OPSEC & detection notes

- 従来の hunter heuristics（AS なしの TGS、数十年単位の lifetime）は golden tickets にも適用されますが、diamond tickets は主に **PAC content または group mapping が不可能に見える場合**に検出されます。自動比較で forgery と即座に判定されないよう、logon hours、user profile paths、device IDs など、すべての PAC field を設定してください。<sup>[[3]](#references)</sup>
- **groups/RIDs を過剰に追加しないでください**。`512`（Domain Admins）と `519`（Enterprise Admins）だけが必要なら、それ以上は追加せず、target account が AD 内の別の場所でもそれらの groups に所属しているよう自然に見えることを確認してください。過剰な `ExtraSids` は明らかな手掛かりになります。
- Sapphire-style swaps は U2U fingerprints を残します。4769 における `ENC-TKT-IN-SKEY` + `additional-tickets`、user（多くの場合 requester）を指す `sname`、および forged ticket を使用した後続の 4624 logon です。単に no-AS-REQ の欠落を探すのではなく、これらの fields を相関させてください。<sup>[[5]](#references)</sup>
- Microsoft は CVE-2026-20833 のため、**RC4 service ticket issuance** を段階的に廃止し始めました。KDC で AES-only etypes を強制すると、domain が harden されるだけでなく、diamond/sapphire tooling とも整合します（/opsec はすでに AES を強制しています）。forged PAC に RC4 を混在させると、今後ますます目立つようになります。<sup>[[6]](#references)</sup>
- Splunk の Security Content project は、diamond tickets 用の attack-range telemetry と、*Windows Domain Admin Impersonation Indicator* などの detections を配布しています。これらは通常とは異なる Event ID 4768/4769/4624 の sequence と PAC group changes を相関させます。その dataset を再生するか、上記の commands で独自に生成すると、T1558.001 に対する SOC coverage を検証しつつ、回避すべき具体的な alert logic を把握できます。<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
