# macOS write-triggered execution research checklist

Working checklist for the [macOS Auto Start](../../src/macos-hardening/macos-auto-start-locations.md) update. A checked item means the mechanism and its current trigger were assessed; it does **not** mean a persistent payload was installed on the research machine. The local machine is macOS 26.5.2. Do not restart, log out, modify live preferences, or change a security database on that machine. Use read-only inspection and disposable, isolated files; a uniquely named, temporary user agent is allowed only with explicit cleanup in `finally`. Mark untested runtime behavior explicitly.

| Area | Status | Questions / evidence still needed |
| --- | --- | --- |
| Existing page inventory and de-duplication | [x] | The current page already covers launchd, shells, login items, cron/at, Folder Actions, many plug-ins, PAM, authorization, Apache, BSM, and older mechanisms. Compare each candidate with those sections before adding it. |
| `launchd` classic locations and plist syntax | [x] | Apple startup guide and the local `launchd.plist(5)` manual; corrected the nonexistent per-user daemon folder and invalid `ProgramArguments`/XML example. |
| Modern Service Management / Background Task Management | [ ] | `SMAppService`, bundled agents/daemons/login items, registration/approval and `sfltool` visibility. [Apple API](https://developer.apple.com/documentation/servicemanagement/smappservice), [registration semantics](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29). Distinguish writing a bundle from registering it. |
| Existing jobs with writable executables or configuration | [ ] | Enumerate active plist `Program`, `ProgramArguments`, `WatchPaths`, `QueueDirectories`, `StartOnMount`; record only generic patterns, no private paths. Test only with a synthetic plist in a temporary directory. |
| Shell startup and application command hooks | [ ] | zsh/bash login versus interactive startup, `ZDOTDIR`, SSH commands, Terminal/iTerm profiles; isolated `ZDOTDIR`/`HOME` test. |
| Apple user plug-ins | [ ] | Scripting additions, Input Methods, Audio Units, Quick Look, Spotlight, Finder Sync, ColorPickers, screen savers, Services; identify actual activation and signing/approval requirements. [Apple Library directory guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html). |
| App-specific triggers | [ ] | iTerm, Chrome native messaging, VS Code tasks/extensions, Alfred, Hammerspoon, BetterTouchTool, xbar, Raycast, Karabiner, Automator/Shortcuts. Document installed-app and user-consent prerequisites; avoid presenting every config file as automatic execution. |
| Scheduled/event mechanisms | [ ] | cron, at, Folder Actions, Calendar alerts, `launchd` path/mount/time triggers; check enabled state and event conditions on current macOS. |
| Privileged legacy mechanisms | [ ] | PAM, Authorization Plugins, BSM `audit_warn`, Apache, CUPS, `man.conf`, StartupItems, `emond`, periodic, XQuartz, kexts; mark absent/deprecated/disabled mechanisms. Periodic components are absent locally. |
| Other developer-tool hooks | [ ] | Git hooks, editor init files, debugger init files, package manager hooks, build tool configs. Decide which require prior user/project action and whether they belong under conditional execution. |
| Safe PoC review | [ ] | For each added section: exact writable path, trigger, execution identity, prerequisite, marker-only PoC where feasible, cleanup, and whether this Mac was only inspected or actually tested. No sudo, reboot, logout, live login item, auth database, or persistent service registration in local tests. |
| Final review and PR integration | [ ] | Re-read the page and PR diff for duplicate techniques, broken links, stale claims, Markdown build, and changes made by the other contributor before each push. |

## Local read-only observations (5 October 2026)

- Present: `/usr/sbin/cron`, `/usr/libexec/atrun`, `/etc/man.conf`, `/etc/security/audit_warn`, and user Library directories for LaunchAgents, Input Methods, Audio Units, ScriptingAdditions, Spotlight, QuickLook, and screen savers.
- Absent: `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, and `/System/Library/LaunchDaemons/com.apple.periodic-daily.plist`. A system or user `~/Library/LaunchDaemons` is not a documented scanned location.
- iTerm, Google Chrome, and Visual Studio Code are installed; Hammerspoon, BetterTouchTool, Alfred, Karabiner-Elements, and xbar were not found in `/Applications` under their usual names. This says nothing about other install locations.
- These checks establish path and component presence only. They do not establish that a particular service or plug-in is enabled or that a PoC executes.

## Contributor A verified progress

- [x] `launchd` `WatchPaths`: a unique temporary user agent was bootstrapped in `gui/<uid>`, a file in a temporary directory was changed, a marker appeared, and `bootout` succeeded. The self-cleaning PoC is on the page. Apple's launchd guide documents `WatchPaths` and `QueueDirectories`; `StartOnMount` remains documentation-only here.
- [x] zsh startup order: isolated `ZDOTDIR` test observed `-c` → `zshenv`, `-ic` → `zshenv zshrc`, `-lc` → `zshenv zprofile zlogin`, `-lic` → all plus `zlogout`. No real dotfile was changed.
- [x] Git `post-checkout` hook: executed a marker in a temporary repository after a branch switch, then removed the repository.
- [x] Vim `~/.vimrc`: executed a marker with a temporary `HOME`, then removed it. Neovim was not installed locally and is documentation-only.
- [ ] VS Code `runOn: folderOpen`: official documentation confirms the trusted-workspace and automatic-task approval gates; VS Code 1.139.1 is installed. The active desktop was not used for a runtime test.
- [ ] Chrome native messaging: official Chrome documentation confirms manifest paths, extension permissions, allowed origins, and host startup on `connectNative`/`sendNativeMessage`. Chrome and both standard manifest directories exist locally. The active Chrome profile was not changed or used for a runtime test.
- [x] Classic user and system launchd plist inventory (read only): parsed 464 system agents, 422 system daemons, 6 `/Library` agents, 7 `/Library` daemons, and 9 user agents. `WatchPaths` occurred in 4 system agents and 4 system daemons; `QueueDirectories` in 2 and 5; `StartOnMount` in 1 system daemon. Nine user plists and two absolute `Program`/first-argument targets were writable according to `os.access`, which does not prove a job is enabled, signature validation would pass, or a sandbox could write them. App-bundled helpers and interpreted arguments still need review.
- [x] Modern Service Management paths and approval rules were checked against Apple's `SMAppService` docs and a read-only local bundle inventory; multiple bundled helper entries were found in `/Applications`. A mere write to an unregistered helper does not make it a login item.

## Contributor B (Opus 4.8) — coordination log

To avoid duplicated techniques on the shared PR. **Done / already in the page (do not re-add):**

- [x] **Application Script Files** (theevilbit 10) — user-writable interpreted scripts shipped in/used by apps (Sublime `sublime.py`, Homebrew `brew`, IDLE `idlemain.py`, Wireshark `ChmodBPF`). Added under *Conditional Sandbox Bypass*. Validated read-only: `/opt/homebrew/bin/brew` is a user-writable Bash script on this host.
- [x] **Dock Tile Plugins** (theevilbit 32) — `NSDockTilePlugIn` loaded into the non-sandboxed, unsigned `com.apple.dock.external.extra` XPC helper; not shown in BTM. Added under *Conditional*. Validated: Calendar/App Store/System Settings + 3rd-party Warp/ChatGPT declare it on macOS 26.
- [x] **Widgets / WidgetKit** (theevilbit 33) — `com.apple.notificationcenterui.plist` `widgets.instances`. Added under *Conditional*.
- [x] **launchd Boot Tasks** (theevilbit 34) — `__TEXT,__config` tasks (`/etc/rc.server`, `deferred_install`, …). Added under *Root*.
- [x] **NVRAM `apple-trusted-trampoline`** (theevilbit 35) — strike-through/impractical note under *Root* (needs SIP off + Apple-signed payload).

**Contributor B will take next (claiming to avoid overlap):** Configuration Profiles (`.mobileconfig`) deploying agents; Mail.app rules (Run AppleScript); Calendar.app alerts (run script / open file); `~/.ssh/config` `LocalCommand`/`ProxyCommand`/`Match exec`; debugger init files (`~/.lldbinit`, `~/.gdbinit`); `LESSOPEN`/pager hooks.

**Left to Contributor A (your existing table):** SMAppService/BTM, WatchPaths/QueueDirectories/StartOnMount, shell startup refinements, Apple user plug-ins (Input Methods, Scripting Additions, Services/Quick Actions), per-app triggers (Chrome native messaging, VS Code, Raycast, Karabiner, Automator/Shortcuts), git hooks / editor init / package-manager hooks, legacy privileged review.

Ping convention: before adding anything from the other side's list, grep the page for the `###` heading first.

### Contributor B — batch 2 scope update (de-conflicted with Contributor A's table)

Contributor A's table already broadly claims shell/SSH, Apple user plug-ins, dev-tool hooks (git/debugger/editor init), scheduled/event (incl. Calendar alerts), and BTM/SMAppService. To avoid duplication, **Contributor B releases** the earlier claims on *SSH config*, *Calendar alerts*, and *debugger init* back to Contributor A, and will add only these **unique** items not present in A's table:

- [x] **Mail.app AppleScript rules** — `~/Library/Mail/V10/MailData/SyncedRules.plist` (+ iCloud `ubiquitous_SyncedRules.plist`). *Conditional.*
- [x] **Configuration Profiles (`.mobileconfig`)** — control/MITM persistence (root CA, proxy, managed prefs, `PayloadRemovalDisallowed`). Accuracy note baked in: a profile CANNOT drop an arbitrary LaunchDaemon/Agent without MDM. *Conditional.*
- [x] **DYLD_INSERT_LIBRARIES env persistence** — via LaunchAgent `EnvironmentVariables`; plus dead `~/.MacOSX/environment.plist` (gone 10.8) and `/etc/launchd.conf` (gone 10.10). Cross-links existing dyld page. *Conditional.*
- [x] **storagekitd SIP bypass (CVE-2024-44243)** — `/Library/Filesystems/` bundle → persistent kexts / SIP-protected writes (fixed 15.2). *Root.*
- [x] **`/etc/paths`, `/etc/paths.d/*` PATH hijack** — `path_helper` from `/etc/zprofile`. *Root.*

Accuracy reminders for whoever writes BTM: CVE-2022-42821 is Gatekeeper ("Achilles"), **not** a BTM bypass; the real BTM bypasses are Wardle's behavioral ones (`sfltool resetbtm`, SIGSTOP the agent) with no CVE.

### Contributor B — batch 3 scope (AI coding-agent CLIs + browser extensions)

Unclaimed by A's table (A took VS Code tasks + Chrome native messaging). B is adding:

- [x] **AI coding-agent CLIs** — config files that run shell/launch processes when the dev uses the tool. Validated present on this host: Claude Code (`~/.claude/settings.json` has `hooks`+`statusLine`), Codex (`~/.codex/config.toml` with `[mcp_servers.*]` launching `command`), Gemini (`~/.gemini/settings.json` `hooks`), Cursor (`~/.cursor/hooks.json` with `beforeShellExecution` etc.). Ref: CVE-2025-59536 (Check Point). *Conditional.*
- [x] **Chromium External Extensions + enterprise-policy force-install** — `External Extensions/*.json` auto-install and `ExtensionInstallForcelist` managed pref (Chrome `com.google.Chrome`, Brave `com.brave.Browser`, Edge `com.microsoft.Edge`). Explicitly NOT native messaging (A's). *Conditional.*

B will NOT touch: Chrome native messaging, VS Code tasks (A owns these).

(Status: batch 3 committed — AI CLIs incl. Claude managed-settings root path; Chromium External Extensions + ExtensionInstallForcelist + cross-link to macos-chromium-injection for Secure Preferences.)
