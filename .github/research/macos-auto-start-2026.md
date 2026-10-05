# macOS write-triggered execution research checklist

Working checklist for the [macOS Auto Start](../../src/macos-hardening/macos-auto-start-locations.md) update. A checked item means the mechanism and its current trigger were assessed; it does **not** mean a payload was installed on the research machine. The local machine is macOS 26.5.2. Do not register a job, restart, log out, modify live preferences, or change a security database on that machine. Use read-only inspection and disposable, isolated files; mark untested runtime behavior explicitly.

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
| Safe PoC review | [ ] | For each added section: exact writable path, trigger, execution identity, prerequisite, marker-only PoC where feasible, cleanup, and whether this Mac was only inspected or actually tested. No sudo, reboot, logout, live login item, auth database, or service registration in local tests. |
| Final review and PR integration | [ ] | Re-read the page and PR diff for duplicate techniques, broken links, stale claims, Markdown build, and changes made by the other contributor before each push. |

## Local read-only observations (5 October 2026)

- Present: `/usr/sbin/cron`, `/usr/libexec/atrun`, `/etc/man.conf`, `/etc/security/audit_warn`, and user Library directories for LaunchAgents, Input Methods, Audio Units, ScriptingAdditions, Spotlight, QuickLook, and screen savers.
- Absent: `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, and `/System/Library/LaunchDaemons/com.apple.periodic-daily.plist`. A system or user `~/Library/LaunchDaemons` is not a documented scanned location.
- iTerm, Google Chrome, and Visual Studio Code are installed; Hammerspoon, BetterTouchTool, Alfred, Karabiner-Elements, and xbar were not found in `/Applications` under their usual names. This says nothing about other install locations.
- These checks establish path and component presence only. They do not establish that a particular service or plug-in is enabled or that a PoC executes.
