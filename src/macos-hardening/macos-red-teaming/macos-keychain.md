# macOS Keychain

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}

## Main Keychains

- The **User Keychain** (`~/Library/Keychains/login.keychain-db`), which is used to store **user-specific credentials** like application passwords, internet passwords, user-generated certificates, network passwords, and user-generated public/private keys.
- The **System Keychain** (`/Library/Keychains/System.keychain`), which stores **system-wide credentials** such as WiFi passwords, system root certificates, system private keys, and system application passwords.
  - It's possible to find other components like certificates in `/System/Library/Keychains/*`
- In **iOS** there is only one **Keychain** located in `/private/var/Keychains/`. This folder also contains databases for the `TrustStore`, certificates authorities (`caissuercache`) and OSCP entries (`ocspache`).
  - Apps will be restricted in the keychain only to their private area based on their application identifier.

### Password Keychain Access

These files, while they do not have inherent protection and can be **downloaded**, are encrypted and require the **user's plaintext password to be decrypted**. A tool like [**Chainbreaker**](https://github.com/n0fate/chainbreaker) could be used for decryption.

## Keychain Entries Protections

### ACLs

Each entry in the keychain is governed by **Access Control Lists (ACLs)** which dictate who can perform various actions on the keychain entry, including:

- **ACLAuhtorizationExportClear**: Allows the holder to get the clear text of the secret.
- **ACLAuhtorizationExportWrapped**: Allows the holder to get the clear text encrypted with another provided password.
- **ACLAuhtorizationAny**: Allows the holder to perform any action.

The ACLs are further accompanied by a **list of trusted applications** that can perform these actions without prompting. This could be:

- **N`il`** (no authorization required, **everyone is trusted**)
- An **empty** list (**nobody** is trusted)
- **List** of specific **applications**.

Also the entry might contain the key **`ACLAuthorizationPartitionID`,** which is use to identify the **teamid, apple,** and **cdhash.**

- If the **teamid** is specified, then in order to **access the entry** value **withuot** a **prompt** the used application must have the **same teamid**.
- If the **apple** is specified, then the app needs to be **signed** by **Apple**.
- If the **cdhash** is indicated, then **app** must have the specific **cdhash**.

### Creating a Keychain Entry

When a **new** **entry** is created using **`Keychain Access.app`**, the following rules apply:

- All apps can encrypt.
- **No apps** can export/decrypt (without prompting the user).
- All apps can see the integrity check.
- No apps can change ACLs.
- The **partitionID** is set to **`apple`**.

When an **application creates an entry in the keychain**, the rules are slightly different:

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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

### APIs

> [!TIP]
> The **keychain enumeration and dumping** of secrets that **won't generate a prompt** can be done with the tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Other API endpoints can be found in [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html) source code.

List and get **info** about each keychain entry using the **Security Framework** or you could also check the Apple's open source cli tool [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Some API examples:

- The API **`SecItemCopyMatching`** gives info about each entry and there are some attributes you can set when using it:
  - **`kSecReturnData`**: If true, it will try to decrypt the data (set to false to avoid potential pop-ups)
  - **`kSecReturnRef`**: Get also reference to keychain item (set to true in case later you see you can decrypt without pop-up)
  - **`kSecReturnAttributes`**: Get metadata about entries
  - **`kSecMatchLimit`**: How many results to return
  - **`kSecClass`**: What kind of keychain entry

Get **ACLs** of each entry:

- With the API **`SecAccessCopyACLList`** you can get the **ACL for the keychain item**, and it will return a list of ACLs (like `ACLAuhtorizationExportClear` and the others previously mentioned) where each list has:
  - Description
  - **Trusted Application List**. This could be:
    - An app: /Applications/Slack.app
    - A binary: /usr/libexec/airportd
    - A group: group://AirPort

Export the data:

- The API **`SecKeychainItemCopyContent`** gets the plaintext
- The API **`SecItemExport`** exports the keys and certificates but might have to set passwords to export the content encrypted

And these are the **requirements** to be able to **export a secret without a prompt**:

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

- **Invisible**: It's a boolean flag to **hide** the entry from the **UI** Keychain app
- **General**: It's to store **metadata** (so it's NOT ENCRYPTED)
  - Microsoft was storing in plain text all the refresh tokens to access sensitive endpoint.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}


