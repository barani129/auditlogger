# auditlogger
AuditLogger is the custom controller to collect audit logs from master nodes of an Openshift cluster and store them into a local postgres db and serve the audit log queries/requests over web as a backend.

## Description
AuditLogger is the custom controller to collect audit logs from master nodes of an Openshift cluster and store them into a local postgres db and serve the audit log queries/requests over web as a backend.

## Getting Started
After the CRD installation, please execute the following command to under each field in the spec.
```sh
kubectl/oc explain auditlogger.monitoring.spark.co.nz
```

### Prerequisites
- go version v1.21.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- Tested on Openshift 4.14 cluster

### To Deploy on the cluster
Sample deployment
1. Create the CRDs
```sh
oc create -f monitoring-wo-webhooks/config/crd/bases/monitoring.spark.co.nz_containerscans.yaml
oc create -f monitoring-wo-webhooks/config/crd/bases/monitoring.spark.co.nz_portscans.yaml
oc create -f monitoring-wo-webhooks/config/crd/bases/monitoring.spark.co.nz_vmscans.yaml
oc create -f monitoring-wo-webhooks/config/crd/bases/monitoring.spark.co.nz_metallbscans.yaml
```
2. Create the service account
```sh
oc project <yourproject>
oc create sa <sa>
```
3. Create roles/rolebindings for service account
Modify service account name in role_binding.yaml
```sh
oc create -f monitoring-wo-webhooks/config/rbac/role.yaml
oc create -f monitoring-wo-webhooks/config/rbac/role_binding.yaml
```
4. Create the deployment of the controller
update the created service account and image name in the deployment file
```sh
oc create deployment -f <deployment.yaml>
```
5. To run as non-root user
update security context, runAsUser and runAsGroup if required.

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/auditlogger:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Using make: Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/auditlogger:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/auditlogger:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/auditlogger/<tag or branch>/dist/install.yaml
```

## License

Copyright 2024 baranitharan.chittharanjan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
