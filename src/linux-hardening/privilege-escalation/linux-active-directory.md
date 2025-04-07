# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Eine Linux-Maschine kann auch in einer Active Directory-Umgebung vorhanden sein.

Eine Linux-Maschine in einem AD könnte **verschiedene CCACHE-Tickets in Dateien speichern. Diese Tickets können wie jedes andere Kerberos-Ticket verwendet und missbraucht werden**. Um diese Tickets zu lesen, müssen Sie der Benutzerbesitzer des Tickets oder **root** auf der Maschine sein.

## Enumeration

### AD Enumeration von Linux

Wenn Sie Zugriff auf ein AD in Linux (oder Bash in Windows) haben, können Sie [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) versuchen, um das AD zu enumerieren.

Sie können auch die folgende Seite überprüfen, um **andere Möglichkeiten zur Enumeration von AD aus Linux** zu lernen:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP-Verzeichnis** mit einem MIT **Kerberos** Key Distribution Center für die Verwaltung ähnlich wie Active Directory. Es nutzt das Dogtag **Zertifikatssystem** für CA- und RA-Zertifikatsmanagement und unterstützt **Multi-Faktor**-Authentifizierung, einschließlich Smartcards. SSSD ist für Unix-Authentifizierungsprozesse integriert. Erfahren Sie mehr darüber in:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Spielen mit Tickets

### Pass The Ticket

Auf dieser Seite finden Sie verschiedene Orte, an denen Sie **Kerberos-Tickets auf einem Linux-Host finden können**. Auf der folgenden Seite können Sie lernen, wie Sie diese CCache-Ticketformate in Kirbi (das Format, das Sie in Windows verwenden müssen) umwandeln und auch, wie Sie einen PTT-Angriff durchführen:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE-Ticket-Wiederverwendung aus /tmp

CCACHE-Dateien sind binäre Formate zum **Speichern von Kerberos-Anmeldeinformationen**, die typischerweise mit 600 Berechtigungen in `/tmp` gespeichert werden. Diese Dateien können an ihrem **Namensformat, `krb5cc_%{uid}`,** identifiziert werden, das mit der UID des Benutzers korreliert. Für die Überprüfung des Authentifizierungstickets sollte die **Umgebungsvariable `KRB5CCNAME`** auf den Pfad der gewünschten Ticketdatei gesetzt werden, um deren Wiederverwendung zu ermöglichen.

Listen Sie das aktuelle Ticket, das für die Authentifizierung verwendet wird, mit `env | grep KRB5CCNAME` auf. Das Format ist portabel und das Ticket kann **durch Setzen der Umgebungsvariable** mit `export KRB5CCNAME=/tmp/ticket.ccache` wiederverwendet werden. Das Kerberos-Ticket-Namensformat ist `krb5cc_%{uid}`, wobei uid die Benutzer-UID ist.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE Ticket-Wiederverwendung aus dem Schlüsselbund

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz der Maschine deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool für diesen Zweck ist unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) zu finden, das die Extraktion erleichtert, indem es in Sitzungen injiziert und Tickets in `/tmp` dumpet.

Um dieses Tool zu konfigurieren und zu verwenden, werden die folgenden Schritte befolgt:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Dieses Verfahren wird versuchen, in verschiedene Sitzungen zu injizieren, wobei der Erfolg durch das Speichern der extrahierten Tickets in `/tmp` mit einer Namenskonvention von `__krb_UID.ccache` angezeigt wird.

### CCACHE-Ticket-Wiederverwendung von SSSD KCM

SSSD hält eine Kopie der Datenbank unter dem Pfad `/var/lib/sss/secrets/secrets.ldb`. Der entsprechende Schlüssel wird als versteckte Datei unter dem Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur lesbar, wenn Sie **root**-Berechtigungen haben.

Das Aufrufen von **`SSSDKCMExtractor`** mit den Parametern --database und --key wird die Datenbank analysieren und **die Geheimnisse entschlüsseln**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Der **Credential Cache Kerberos Blob kann in eine verwendbare Kerberos CCache**-Datei umgewandelt werden, die an Mimikatz/Rubeus übergeben werden kann.

### CCACHE-Ticket-Wiederverwendung aus Keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Konten aus /etc/krb5.keytab extrahieren

Servicekonto-Schlüssel, die für Dienste mit Root-Rechten unerlässlich sind, werden sicher in **`/etc/krb5.keytab`**-Dateien gespeichert. Diese Schlüssel, ähnlich wie Passwörter für Dienste, erfordern strikte Vertraulichkeit.

Um den Inhalt der Keytab-Datei zu überprüfen, kann **`klist`** verwendet werden. Das Tool ist dafür ausgelegt, Schlüsseldetails anzuzeigen, einschließlich des **NT Hash** für die Benutzerauthentifizierung, insbesondere wenn der Schlüsseltyp als 23 identifiziert wird.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Für Linux-Benutzer bietet **`KeyTabExtract`** die Funktionalität, den RC4 HMAC-Hash zu extrahieren, der für die Wiederverwendung des NTLM-Hashes genutzt werden kann.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Auf macOS dient **`bifrost`** als Werkzeug zur Analyse von Keytab-Dateien.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Durch die Nutzung der extrahierten Konten- und Hash-Informationen können Verbindungen zu Servern mit Tools wie **`crackmapexec`** hergestellt werden.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referenzen

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
