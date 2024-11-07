## cli-v2 cluster

Manage clusters of Codefresh runtimes

```
cli-v2 cluster [flags]
```

### Options

```
  -h, --help   help for cluster
```

### Options inherited from parent commands

```
      --auth-context string        Run the next command using a specific authentication context
      --cfconfig string            Custom path for authentication contexts config file (default "/home/user")
      --insecure                   Disable certificate validation for TLS connections (e.g. to g.codefresh.io)
      --insecure-ingress-host      Disable certificate validation of ingress host (default: false)
      --request-timeout duration   Request timeout (default 30s)
```

### SEE ALSO

* [cli-v2](cli-v2.md)	 - cli-v2 is used for installing and managing codefresh installations using gitops
* [cli-v2 cluster add](cli-v2_cluster_add.md)	 - Add a cluster to a given runtime
* [cli-v2 cluster create-argo-rollouts](cli-v2_cluster_create-argo-rollouts.md)	 - creates argo-rollouts component on the target cluster
* [cli-v2 cluster list](cli-v2_cluster_list.md)	 - List all the clusters of a given runtime
* [cli-v2 cluster remove](cli-v2_cluster_remove.md)	 - Removes a cluster from a given runtime

