# Config

Accessor: `client.Config()`

Retrieve and update configuration for sandboxes and the gateway.

## GetSandbox

Retrieve the current configuration for a specific sandbox.

```go
config, err := client.Config().GetSandbox(ctx, "default", "sandbox-123")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Sandbox config: policy_version=%d, revision=%d\n",
    config.PolicyVersion, config.ConfigRevision)
```

`Workspace`, `ConfigurationInstanceID` and `ConfigurationAdmitted` preserve the
Gateway's effective configuration projection. Check the sandbox's reported
admission status separately before treating that configuration as active, including
its `InstanceID` and configuration revisions.

`TrafficIdentityTargets` contains public traffic gateway grants authorized for
that sandbox UUID and workspace: target name, HTTPS endpoint, audience, public TLS
roots, supported transports and target fingerprint. Certificate and transport
slices are copied from the protobuf response. These fields contain no traffic
credential and do not authorize issuing one; issuance is supervisor-only. Older
servers omit the fields, producing false admission and no targets rather than
implied origin attestation.

## GetGateway

Retrieve the gateway-level configuration.

```go
config, err := client.Config().GetGateway(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Gateway settings revision: %d\n", config.SettingsRevision)
```

## Update

Apply a configuration update. The update is validated before being applied.

```go
result, err := client.Config().Update(ctx, "default", &v1.ConfigUpdate{
    Name:       "sandbox-123",
    SettingKey:  "idle_timeout",
    SettingValue: &v1.SettingValue{
        Type:      v1.SettingValueString,
        StringVal: "30m",
    },
})
if err != nil {
    // See [Error Handling](../error-handling.md) for validation errors
    log.Fatal(err)
}
fmt.Printf("Config updated: revision=%d\n", result.SettingsRevision)
```

See also: [Error Handling](../error-handling.md)

`SandboxConfig.ProviderAttachmentEpoch` preserves the gateway-owned provider
attachment lineage. Runtime-origin verifiers must include it in the configuration
digest; a provider revision alone does not identify attachment replacement.
Older servers may omit it, which is not proof of a current attachment.
