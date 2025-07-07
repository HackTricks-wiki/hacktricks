# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** are a feature in Apple's macOS that allows applications to communicate with each other. They are part of the **Apple Event Manager**, which is a component of the macOS operating system responsible for handling interprocess communication. This system enables one application to send a message to another application to request that it perform a particular operation, like opening a file, retrieving data, or executing a command.

The mina daemon is `/System/Library/CoreServices/appleeventsd` which registers the service `com.apple.coreservices.appleevents`.

Every application that can receive events will checking with this daemon providing its Apple Event Mach Port. And when an app wants to send an event to to it, the app will request this port from the daemon.

Sandboxed applications requires privileges like `allow appleevent-send` and `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` in order to be able to send events. Noten that entitlements like `com.apple.security.temporary-exception.apple-events` could restrict who have access to send events which will need entitlements like `com.apple.private.appleevents`.

> [!TIP]
> It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}


