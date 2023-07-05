## Deployment

To Deploy Discovery-engine along with DiscoveredPolicy CRD:

```
kubectl apply -f deployment.yaml
```

## Modifying the Deployment (if needed)

1. Make the required Changes to the manifests for discovery-engine and DiscoveredPolicy CRD & Controller in `default/discovery-engine`, `default/dsp-controller` directory respectively.

2. Generate Manifest
    ```
    make manifests
    ```
3. Apply the Manifest
    ```
    kubectl apply -f deployment.yaml
    ```