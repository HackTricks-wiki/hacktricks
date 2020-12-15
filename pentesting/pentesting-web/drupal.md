# Drupal

## Username enumeration

### Register

In _/user/register_ just try to create a username and if the name is already taken it will be notified:

![](../../.gitbook/assets/image%20%28248%29.png)

### Request new password

If you request a new password for an existing username:

![](../../.gitbook/assets/image%20%28301%29.png)

If you request a new password for a non-existent username:

![](../../.gitbook/assets/image%20%2886%29.png)

## Number of users enumeration

Accessing _/user/&lt;number&gt;_ you can see the number of existing users, in this case is 2 as _/users/3_ returns a not found error:

![](../../.gitbook/assets/image%20%2826%29.png)

![](../../.gitbook/assets/image%20%28227%29%20%281%29%20%281%29.png)

## Hidden pages enumeration

**Fuzz `/node/$` where `$` is a number** \(from 1 to 500 for example\).  
You could find **hidden pages** \(test, dev\) which are not referenced by the search engines.

## Code execution inside Drupal with admin creds

You need the **plugin php to be installed** \(check it accessing to _/modules/php_ and if it returns a **403** then, **exists**, if **not found**, then the **plugin php isn't installed**\)

Go to _Modules_ -&gt; \(**Check**\) _PHP Filter_  -&gt; _Save configuration_

![](../../.gitbook/assets/image%20%28247%29.png)

Then click on _Add content_ -&gt; Select _Basic Page_ or _Article -_&gt; Write _php shellcode on the body_ -&gt; Select _PHP code_ in _Text format_ -&gt; Select _Preview_

![](../../.gitbook/assets/image%20%28266%29.png)

