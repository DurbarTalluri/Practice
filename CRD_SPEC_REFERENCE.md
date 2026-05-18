# Site24x7K8s Custom Resource Specification Reference

This document describes all configurable fields in the `Site24x7K8s` Custom Resource Definition (CRD).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Top-Level Spec Fields](#top-level-spec-fields)
- [Proxy Configuration](#proxy-configuration)
- [Installation Type](#installation-type)
- [Infrastructure Configuration](#infrastructure-configuration)
  - [Site24x7 Agent](#site24x7-agent)
  - [Kube State Metrics](#kube-state-metrics)
  - [Cluster Agent](#cluster-agent)
  - [Service Account](#service-account)
  - [ConfigMap Settings](#configmap-settings)
- [APM Configuration](#apm-configuration)
  - [Agent Images](#agent-images)
  - [Data Exporter](#data-exporter)

---

## Prerequisites

Before creating a `Site24x7K8s` resource, you must create a Secret containing your Site24x7 device key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: site24x7-agent
  namespace: site24x7
type: Opaque
data:
  s247_device_key: <base64-encoded-device-key>
```

---

## Top-Level Spec Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `applyDefaultTolerations` | boolean | `true` | When enabled, applies default tolerations to allow pods to run on control-plane/master nodes |
| `tolerations` | array | `[]` | Custom tolerations to apply to all operator-managed pods |
| `openShift` | boolean | `false` | configure true if OpenShift environment |
| `gkeAutoPilot` | boolean | `false` | configure true if GKE Autopilot environment |
| `applyPriorityClass` | boolean | `true` | Create and apply a PriorityClass to ensure agent pods are scheduled with high priority |
| `priorityClassValue` | integer | `12000000` | Priority value for the PriorityClass (higher values = higher priority) |

---

## Proxy Configuration

Configure HTTP/HTTPS proxy settings for agent communication.

```yaml
spec:
  proxy:
    http_proxy: ""
    https_proxy: ""
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxy.http_proxy` | string | `""` | HTTP proxy URL (e.g., `http://proxy.example.com:8080`) |
| `proxy.https_proxy` | string | `""` | HTTPS proxy URL (e.g., `https://proxy.example.com:8080`) |

---

## Installation Type

Define what type of monitoring to deploy.

```yaml
spec:
  installationType:
    agentType: "custom"
    customOptions:
      server: true
      applications: false
      applogs: false
      plugins: false
      automation: false
      apmInsight: true
      process: false
      resourceChecks: false
```

| Field | Type | Options | Description |
|-------|------|---------|-------------|
| `agentType` | string | `fso`, `apm`, `infra`, `custom` | Predefined monitoring profile or custom selection |

### Agent Types

| Type | Description |
|------|-------------|
| `fso` | Full-Stack Observability - enables all monitoring capabilities |
| `apm` | Application Performance Monitoring only |
| `infra` | Infrastructure monitoring only (Kubernetes + server metrics) |
| `custom` | Custom selection using `customOptions` |

### Custom Options

Only applicable when `agentType: "custom"`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server` | boolean | `true` | Enable server/infrastructure monitoring |
| `applications` | boolean | `false` | Enable application monitoring |
| `applogs` | boolean | `false` | Enable application log collection |
| `plugins` | boolean | `false` | Enable plugin-based monitoring |
| `automation` | boolean | `false` | Enable IT automation features |
| `apmInsight` | boolean | `true` | Enable APM Insight agent injection |
| `process` | boolean | `false` | Enable process monitoring |
| `resourceChecks` | boolean | `false` | Enable resource check monitoring |

---

## Infrastructure Configuration

### Basic Settings

```yaml
spec:
  infrastructure:
    clusterName: "MY-EKS-CLUSTER"
    managementAction: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterName` | string | **Required** | Display name for the Kubernetes cluster in Site24x7 |
| `managementAction` | boolean | `true` | Enable management actions (restart pods, scale deployments) from Site24x7 console |

---

### Site24x7 Agent

The DaemonSet that runs on every node to collect metrics.

```yaml
spec:
  infrastructure:
    site24x7Agent:
      create: true
      annotations: {}
      leaseAPI:
        enabled: true
        leaseDurationSeconds: 30
      updateStrategy:
        type: "RollingUpdate"
        rollingUpdate:
          maxUnavailable: "55%"
      nodeSelector: {}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `create` | boolean | `true` | Whether to create the Site24x7 agent DaemonSet |
| `annotations` | object | `{}` | Additional annotations for the DaemonSet |
| `nodeSelector` | object | `{}` | Node selector for pod scheduling |

#### Lease API Configuration

Leader election settings for high availability:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `leaseAPI.enabled` | boolean | `true` | Enable lease-based leader election |
| `leaseAPI.leaseDurationSeconds` | integer | `30` | Duration of leadership lease in seconds |

#### Update Strategy

Controls DaemonSet rolling updates:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `updateStrategy.type` | string | `RollingUpdate` | Update strategy type (`RollingUpdate` or `OnDelete`) |
| `updateStrategy.rollingUpdate.maxUnavailable` | string | `55%` | Maximum pods unavailable during update (number or percentage) |

#### Site24x7 Agent Container

```yaml
site24x7AgentContainer:
  image:
    repository: "site24x7"
    name: "docker-agent"
    tag: "release22100"
    pullPolicy: "Always"
  resources:
    limits:
      memory: "1Gi"
  installerName: "kubernetes"
  extraEnv: []
  securityContext: {}
  applyNonRootSecurityContext: false
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `image.repository` | string | `site24x7` | Docker registry/repository |
| `image.name` | string | `docker-agent` | Image name |
| `image.tag` | string | `release22100` | Image tag/version |
| `image.pullPolicy` | string | `Always` | Image pull policy (`Always`, `IfNotPresent`, `Never`) |
| `resources` | object | See example | Resource requests and limits |
| `installerName` | string | `kubernetes` | Installer identifier for agent registration |
| `extraEnv` | array | `[]` | Additional environment variables |
| `securityContext` | object | `{}` | Container security context |
| `applyNonRootSecurityContext` | boolean | `false` | Run container as non-root user |

#### Auto Profiler Container

Sidecar container for automatic APM agent injection:

```yaml
autoProfilerContainer:
  image:
    repository: "durbar99"
    name: "apminsight-autoprofiler"
    tag: "latest"
    pullPolicy: "Always"
  extraEnv:
    - name: "<ENV NAME>"
      value: "ENV VALUE"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `image.repository` | string | - | Docker registry/repository for autoprofiler |
| `image.name` | string | - | Autoprofiler image name |
| `image.tag` | string | - | Autoprofiler image tag |
| `image.pullPolicy` | string | `Always` | Image pull policy |
| `extraEnv` | array | `[]` | Additional environment variables (e.g., custom APM endpoint) |

---

### Kube State Metrics

Deployment for collecting Kubernetes object metrics.

```yaml
spec:
  infrastructure:
    site24x7KubeStateMetrics:
      create: true
      annotations: {}
      updateStrategy: {}
      nodeSelector: {}
      securityContext: {}
      replicas: 1
      image:
        repository: "registry.k8s.io"
        name: "kube-state-metrics/kube-state-metrics"
        tag: "v2.9.2"
        pullPolicy: "IfNotPresent"
        imagePullSecrets: []
      resources:
        requests:
          cpu: "10m"
          memory: "100Mi"
        limits:
          cpu: "200m"
          memory: "256Mi"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `create` | boolean | `true` | Whether to create Kube State Metrics deployment |
| `replicas` | integer | `1` | Number of replicas |
| `annotations` | object | `{}` | Additional annotations |
| `updateStrategy` | object | `{}` | Deployment update strategy |
| `nodeSelector` | object | `{}` | Node selector for scheduling |
| `securityContext` | object | `{}` | Pod security context |
| `image.*` | object | See example | Container image configuration |
| `image.imagePullSecrets` | array | `[]` | Image pull secrets for private registries |
| `resources` | object | See example | Resource requests and limits |

---

### Cluster Agent

Deployment for cluster-wide monitoring and coordination.

```yaml
spec:
  infrastructure:
    site24x7ClusterAgent:
      create: true
      replicas: 1
      annotations: {}
      updateStrategy: {}
      nodeSelector: {}
      securityContext: {}
      image:
        repository: "site24x7"
        name: "docker-agent"
        tag: "cluster_agent_nonroot"
        pullPolicy: "IfNotPresent"
        imagePullSecrets: []
      resources:
        limits:
          cpu: "600m"
          memory: "1Gi"
      livenessProbe: {}
      readinessProbe: {}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `create` | boolean | `true` | Whether to create the Cluster Agent deployment |
| `replicas` | integer | `1` | Number of replicas (typically 1 for leader election) |
| `annotations` | object | `{}` | Additional annotations |
| `updateStrategy` | object | `{}` | Deployment update strategy |
| `nodeSelector` | object | `{}` | Node selector for scheduling |
| `securityContext` | object | `{}` | Pod security context |
| `image.*` | object | See example | Container image configuration |
| `resources` | object | See example | Resource requests and limits |
| `livenessProbe` | object | `{}` | Custom liveness probe configuration |
| `readinessProbe` | object | `{}` | Custom readiness probe configuration |

---

### Service Account

Service account configuration for all operator-managed workloads.

```yaml
spec:
  infrastructure:
    serviceAccount:
      create: true
      annotations: {}
      name: "site24x7"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `create` | boolean | `true` | Whether to create the service account |
| `annotations` | object | `{}` | Annotations (e.g., for IAM role binding in EKS) |
| `name` | string | `site24x7` | Service account name |

---

### ConfigMap Settings

Configuration for data collection intervals and agent settings.

```yaml
spec:
  infrastructure:
    site24x7ConfigMap:
      create: true
      nodeAgentVersion: "2000"
      clusterAgentVersion: "100"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `create` | boolean | `true` | Whether to create the ConfigMap |
| `nodeAgentVersion` | string | `2000` | Node agent configuration version |
| `clusterAgentVersion` | string | `100` | Cluster agent configuration version |

#### One Minute Polling (oneMin)

Resource polling configuration with 1-minute granularity. Value `-1` disables collection.

```yaml
oneMin:
  Pods: "90"
  Nodes: "90"
  Namespaces: "90"
  HorizontalPodAutoscalers: "-1"
  DaemonSets: "90"
  Deployments: "60"
  Endpoints: "-1"
  ReplicaSets: "-1"
  StatefulSets: "90"
  Services: "-1"
  PV: "-1"
  PersistentVolumeClaims: "-1"
  Jobs: "-1"
  Ingresses: "-1"
```

| Field | Type | Description |
|-------|------|-------------|
| `Pods` | string | Pods collection interval (seconds), `-1` to disable |
| `Nodes` | string | Nodes collection interval |
| `Namespaces` | string | Namespaces collection interval |
| `HorizontalPodAutoscalers` | string | HPA collection interval |
| `DaemonSets` | string | DaemonSets collection interval |
| `Deployments` | string | Deployments collection interval |
| `Endpoints` | string | Endpoints collection interval |
| `ReplicaSets` | string | ReplicaSets collection interval |
| `StatefulSets` | string | StatefulSets collection interval |
| `Services` | string | Services collection interval |
| `PV` | string | PersistentVolumes collection interval |
| `PersistentVolumeClaims` | string | PVC collection interval |
| `Jobs` | string | Jobs collection interval |
| `Ingresses` | string | Ingresses collection interval |

#### Settings

Internal collector configuration (in seconds):

```yaml
settings:
  kubernetes: "300"
  daemonsets: "300"
  deployments: "300"
  # ... more settings
```

| Category | Fields | Description |
|----------|--------|-------------|
| **Resource Collectors** | `kubernetes`, `daemonsets`, `deployments`, `statefulsets`, `pods`, `nodes`, `services`, `replicasets`, `ingresses`, `jobs`, `pv`, `persistentvolumeclaim`, `componentstatuses`, `horizontalpodautoscalers`, `endpoints`, `namespaces` | Collection intervals for Kubernetes resources |
| **Event & Data Collectors** | `eventcollector`, `npcdatacollector`, `npcdatacollector_discovery`, `workloadsdatacollector`, `workloadsdatacollector_discovery`, `sidecarnpccollector`, `sidecarnpccollector_discovery` | Event and network performance collection |
| **Processors** | `resourcedependency`, `clustermetricsaggregator`, `ksmprocessor`, `kubeletdatapersistence`, `servicerelationdataprocessor` | Data processing intervals |
| **Control Settings** | `dcinit`, `clusteragent`, `ksm`, `termination`, `kubelet`, `metadata`, `yamlfetcher` | Agent control intervals |
| **Integrations** | `prometheus_integration`, `plugin_integration`, `database_integration` | Integration enable flags (`1` = enabled) |
| **Guidance** | `guidancemetrics` | Best practices recommendations collection |

---

## APM Configuration

Application Performance Monitoring settings for automatic agent injection.

```yaml
spec:
  apm:
    monitorAllPods: true
    includeAppLabels:
      javaApp:
        - app: "sample-java-app"
    excludeAppLabels: {}
    agentsImagePullSecrets: []
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `monitorAllPods` | boolean | `true` | Inject APM agents into all eligible pods |
| `includeAppLabels` | object | `{}` | Label selectors to include pods for APM injection |
| `excludeAppLabels` | object | `{}` | Label selectors to exclude pods from APM injection |
| `agentsImagePullSecrets` | array | `[]` | Image pull secrets for APM agent images |

### Include/Exclude Labels

Target specific applications for monitoring:

```yaml
includeAppLabels:
  # Namespace: production 
  production:
    - app: payment-service
      tier: backend
    - app: order-service
      tier: backend 
  staging:
    - app: payment-service
    - app: inventory-service

excludeAppLabels:
  default:
    - app: "legacy-service"
```

---

### Agent Images

Configure container images for each language-specific APM agent.

#### Java Agent

```yaml
java:
  image:
    repository: "site24x7"
    name: "apminsight-javaagent"
    tag: "7.7.1"
    pullPolicy: "Always"
    imagePullSecrets: []
```

#### Python Agent

```yaml
python:
  image:
    repository: "site24x7"
    name: "apminsight-pythonagent"
    tag: "latest"
    pullPolicy: "Always"
    imagePullSecrets: []
```

#### Node.js Agent

```yaml
nodeJS:
  image:
    repository: "site24x7"
    name: "apminsight-nodejsagent"
    tag: "latest"
    pullPolicy: "Always"
    imagePullSecrets: []
```

#### .NET Agent

```yaml
dotNet:
  image:
    repository: "site24x7"
    name: "apminsight-dotnetagent"
    tag: "latest"
    pullPolicy: "Always"
    imagePullSecrets: []
```

**Common Image Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `repository` | string | Docker registry/repository |
| `name` | string | Image name |
| `tag` | string | Image tag/version |
| `pullPolicy` | string | Image pull policy (`Always`, `IfNotPresent`, `Never`) |
| `imagePullSecrets` | array | Secrets for private registry authentication |

---

### Data Exporter

Configuration for APM data export.

```yaml
dataExporter:
  image:
    repository: ""
    name: ""
    tag: ""
    pullPolicy: ""
    imagePullSecrets: []
  deploymentStrategy: "daemonset"
```

| Field | Type | Options | Description |
|-------|------|---------|-------------|
| `image.*` | object | - | Container image configuration |
| `deploymentStrategy` | string | `daemonset`, `sidecar` | How to deploy the data exporter |

**Deployment Strategies:**

| Strategy | Description |
|----------|-------------|
| `daemonset` | Deploy one exporter per node (most recommended) |
| `sidecar` | Deploy as sidecar container in each monitored pod |

---

## Complete Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: site24x7-agent
  namespace: site24x7
type: Opaque
data:
  s247_device_key: <your-base64-encoded-key>
---
apiVersion: site24x7.com/v1alpha1
kind: Site24x7K8s
metadata:
  namespace: site24x7
  name: site24x7k8s-resource
spec:
  applyDefaultTolerations: true
  openShift: false
  gkeAutoPilot: false
  applyPriorityClass: true
  priorityClassValue: 12000000
  
  proxy:
    http_proxy: ""
    https_proxy: ""
  
  installationType:
    agentType: "fso"  # Full-stack observability
  
  infrastructure:
    clusterName: "production-cluster"
    managementAction: true
    
    site24x7Agent:
      create: true
      site24x7AgentContainer:
        image:
          repository: "site24x7"
          name: "docker-agent"
          tag: "release22100"
        resources:
          limits:
            memory: "1Gi"
    
    site24x7KubeStateMetrics:
      create: true
      replicas: 1
    
    site24x7ClusterAgent:
      create: true
      replicas: 1
    
    serviceAccount:
      create: true
      name: "site24x7"
  
  apm:
    monitorAllPods: true
    java:
      image:
        repository: "site24x7"
        name: "apminsight-javaagent"
        tag: "7.7.1"
    dataExporter:
      deploymentStrategy: "daemonset"
```

---

## Notes

1. **Namespace**: The operator expects all resources to be deployed in the `site24x7` namespace by default.

2. **Secret Requirement**: The `site24x7-agent` Secret must exist before creating the `Site24x7K8s` resource.

3. **RBAC**: The operator automatically creates necessary RBAC resources (ClusterRole, ClusterRoleBinding).

4. **CSI Driver**: For APM agent injection, the operator deploys a CSI driver to mount agent binaries into pods.

5. **Webhook**: A MutatingWebhookConfiguration is created to intercept pod creation and inject APM agents.

6. **APM**: APM Injection does not work for GKE Autopilot environment
