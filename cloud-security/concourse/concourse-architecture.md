# Concourse Architecture

## Architecture

![](<../../.gitbook/assets/image (651).png>)

### ATC: web UI & build scheduler

The ATC is the heart of Concourse. It runs the **web UI and API** and is responsible for all pipeline **scheduling**. It **connects to PostgreSQL**, which it uses to store pipeline data (including build logs).

The [checker](https://concourse-ci.org/checker.html)'s responsibility is to continously checks for new versions of resources. The [scheduler](https://concourse-ci.org/scheduler.html) is responsible for scheduling builds for a job and the [build tracker](https://concourse-ci.org/build-tracker.html) is responsible for running any scheduled builds. The [garbage collector](https://concourse-ci.org/garbage-collector.html) is the cleanup mechanism for removing any unused or outdated objects, such as containers and volumes.

### TSA: worker registration & forwarding

The TSA is a **custom-built SSH server** that is used solely for securely **registering** [**workers**](https://concourse-ci.org/internals.html#architecture-worker) with the [ATC](https://concourse-ci.org/internals.html#component-atc).

The TSA by **default listens on port `2222`**, and is usually colocated with the [ATC](https://concourse-ci.org/internals.html#component-atc) and sitting behind a load balancer.

The **TSA implements CLI over the SSH connection,** supporting [**these commands**](https://concourse-ci.org/internals.html#component-tsa).

### Workers

In order to execute tasks concourse must have some workers. These workers **register themselves** via the [TSA](https://concourse-ci.org/internals.html#component-tsa) and run the services [**Garden**](https://github.com/cloudfoundry-incubator/garden) and [**Baggageclaim**](https://github.com/concourse/baggageclaim).

* **Garden**: This is the **Container Manage AP**I, usually run in **port 7777** via **HTTP**.
* **Baggageclaim**: This is the **Volume Management API**, usually run in **port 7788** via **HTTP**.
