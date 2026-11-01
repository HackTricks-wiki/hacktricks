# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- The **User Keychain** (`~/Library/Keychains/login.keychain-db`), which is used to store **user-specific credentials** like application passwords, internet passwords, user-generated certificates, network passwords, and user-generated public/private keys.
- The **System Keychain** (`/Library/Keychains/System.keychain`), which stores **system-wide credentials** such as WiFi passwords, system root certificates, system private keys, and system application passwords.<sup>[[1]](#references)</sup>
  - It's possible to find other components like certificates in `/System/Library/Keychains/*`
- The per-user **data protection keychain** appears as **Local Items** or **iCloud** in Keychain Access. It is separate from `login.keychain-db` and includes both local-only and synchronizable items; `security` is primarily a file-based-keychain tool, so a short `dump-keychain` result does not rule out credentials here.<sup>[[5]](#references)</sup>
- In **iOS** there is only one **Keychain** located in `/private/var/Keychains/`. This folder also contains databases for the `TrustStore`, certificates authorities (`caissuercache`) and OSCP entries (`ocspache`).
  - Apps will be restricted in the keychain only to their private area based on their application identifier.

### Password Keychain Access

A copied **file-based** keychain is not plaintext. Offline decryption of its protected items needs the keychain password or equivalent key material; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) targets this format.<sup>[[1]](#references)</sup> This is different from a live read in an unlocked user session, where item access controls may allow the read or trigger a prompt without requiring the login password again. The data protection keychain has a different protection and access-group model.<sup>[[5]](#references)</sup>

## Keychain Entries Protections

### File-based keychain ACLs

The `SecAccess` ACL and partition-list rules below describe **file-based** keychains. Data protection keychain items instead use code-signing access groups and optional `SecAccessControl` conditions; do not infer their accessibility from a file-based ACL dump.<sup>[[5]](#references)</sup>

Each entry in a file-based keychain is governed by **Access Control Lists (ACLs)** which dictate who can perform various actions on the keychain entry, including:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Allows the holder to get the clear text of the secret.
- **`kSecACLAuthorizationExportWrapped`**: Allows the holder to get the clear text encrypted with another provided password.
- **`kSecACLAuthorizationAny`**: Allows the holder to perform any action.

The ACLs are further accompanied by a **list of trusted applications** that can perform these actions without prompting. This could be:<sup>[[1]](#references)</sup>

- **N`il`** (no authorization required, **everyone is trusted**)
- An **empty** list (**nobody** is trusted)
- **List** of specific **applications**.

Also the entry might contain the key **`kSecACLAuthorizationPartitionID`,** which is used to identify the **teamid, apple,** and **cdhash.**<sup>[[1]](#references)[[2]](#references)</sup>

- If the **teamid** is specified, the application must have the **same teamid** to **access the entry** value **without** a **prompt**.
- If the **apple** is specified, then the app needs to be **signed** by **Apple**.
- If the **cdhash** is indicated, then **app** must have the specific **cdhash**.

### Creating a file-based keychain entry

When a **new** **entry** is created using **`Keychain Access.app`**, the following rules apply:<sup>[[1]](#references)</sup>

- All apps can encrypt.
- **No apps** can export/decrypt (without prompting the user).
- All apps can see the integrity check.
- No apps can change ACLs.
- The **partitionID** is set to **`apple`**.

When an **application creates an entry in the keychain**, the rules are slightly different:<sup>[[1]](#references)</sup>

- All apps can encrypt.
- Only the **creating application** (or any other apps explicitly added) can export/decrypt (without prompting the user).
- All apps can see the integrity check.
- No apps can change the ACLs.
- The **partitionID** is set to **`teamid:[teamID here]`**.

## Accessing the Keychain

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` sets the item's partition list, while `-k` supplies the current Keychain password required to make that change; the password-taking flag is deprecated.<sup>[[4]](#references)</sup> A successful update does not prove that a later read will be silent: one observed, disabled prototype still triggered a confirmation prompt when it queried the item through `Security.framework`. A matching partition ID is only one part of the ACL and trusted-application checks described above, so verify the actual read path.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> The **keychain enumeration and dumping** of secrets that **won't generate a prompt** can be done with the tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Other API endpoints can be found in [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code.

List and get **info** about each keychain entry using the **Security Framework** or you could also check the Apple's open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Some API examples:<sup>[[1]](#references)</sup>

- The API **`SecItemCopyMatching`** gives info about each entry and there are some attributes you can set when using it:
  - **`kSecReturnData`**: If true, it will try to decrypt the data (set to false to avoid potential pop-ups)
  - **`kSecReturnRef`**: Get an object reference for a key, certificate, or identity; password items do not have this object representation. Use `kSecReturnPersistentRef` to identify a password for a later, targeted query.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Get metadata about entries
  - **`kSecMatchLimit`**: How many results to return
  - **`kSecClass`**: What kind of keychain entry

Get **ACLs** of each entry:<sup>[[1]](#references)</sup>

- With the API **`SecAccessCopyACLList`** you can get the **ACL for the keychain item**. It returns a list of ACLs (such as `kSecACLAuthorizationExportClear` and the others previously mentioned), where each entry has:<sup>[[1]](#references)[[2]](#references)</sup>
  - Description
  - **Trusted Application List**. This could be:
    - An app: /Applications/Slack.app
    - A binary: /usr/libexec/airportd
    - A group: group://AirPort

Export the data:<sup>[[1]](#references)</sup>

- The API **`SecKeychainItemCopyContent`** gets the plaintext
- The API **`SecItemExport`** exports the keys and certificates but might have to set passwords to export the content encrypted

And these are the **requirements** to be able to **export a secret without a prompt**:<sup>[[1]](#references)</sup>

- If **1+ trusted** apps listed:
  - Need the appropriate **authorizations** (**`Nil`**, or be **part** of the allowed list of apps in the authorization to access the secret info)
  - Need code signature to match **PartitionID**
  - Need code signature to match that of one **trusted app** (or be a member of the right KeychainAccessGroup)
- If **all applications trusted**:
  - Need the appropriate **authorizations**
  - Need code signature to match **PartitionID**
    - If **no PartitionID**, then this isn't needed

> [!CAUTION]
> Therefore, if there is **1 application listed**, you need to **inject code in that application**.
>
> If **apple** is indicated in the **partitionID**, you could access it with **`osascript`** so anything that is trusting all applications with apple in the partitionID. **`Python`** could also be used for this.

### Two additional attributes

- **Invisible**: It's a boolean flag to **hide** the entry from the **UI** Keychain app<sup>[[1]](#references)</sup>
- **General**: It's to store **metadata** (so it's NOT ENCRYPTED)<sup>[[1]](#references)</sup>
  - Microsoft was storing in plain text all the refresh tokens to access sensitive endpoint.<sup>[[1]](#references)</sup>

### Data protection keychain: enumerate, then query one item

Run `SecItemCopyMatching` from a **signed app in the target user's login context** with `kSecUseDataProtectionKeychain: true`; do not assume `security dump-keychain` or a default SecItem query searched this store. The caller sees only its authorized access groups.<sup>[[5]](#references)</sup>

If testing code runs inside another process, its data protection keychain access follows that host executable's entitlements. Inspect the actual signed entitlements with `codesign -d --entitlements - /path/to/Target.app` and see [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) for related checks.<sup>[[7]](#references)</sup>

First request **attributes only** for one item class. `kSecAttrSynchronizableAny` includes both local and iCloud-synchronizable matches; omitting it excludes synchronizable items.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` avoids authentication UI during broad enumeration, at the cost of skipping protected matches.<sup>[[9]](#references)</sup> Repeat with `kSecClassInternetPassword` if needed.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

For a permitted secret read, build a **new**, narrow query for the selected item (for example, class, service and account), set `kSecReturnData: true` and `kSecMatchLimit: kSecMatchLimitOne`, and expect item-specific authentication or an error. Do **not** combine `kSecReturnData` with `kSecMatchLimitAll` for password items.<sup>[[10]](#references)</sup> An `errSecItemNotFound` result can also reflect the wrong store, sync filter, or missing access-group entitlement rather than an absent credential.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - A new version of the MacSync macOS stealer targets crypto enthusiasts and developers](https://securelist.com/macsync-new-version/121383/)
- [4] [Apple security(1) man page mirror](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — On Mac keychain APIs and implementations](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Fundamentals](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Pitfalls and Best Practices](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Accessing Keychain Items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
