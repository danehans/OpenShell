# Client

Constructor: `v1.NewClient(config)`

`Client` is the root entry point for SDK operations. It provides typed accessors
for each resource domain and manages the underlying gRPC connection. The
`ClientInterface` covers the stable core accessors; additive helpers such as
`SandboxTemplates()` are available on the concrete client.

## Methods

| Accessor | Returns | Description |
|----------|---------|-------------|
| `Sandboxes()` | `SandboxInterface` | Sandbox lifecycle management |
| `SandboxTemplates()` | `SandboxTemplateInterface` | Reusable sandbox template management |
| `Admission()` | `AdmissionInterface` | Optional administrator-owned workload holds |
| `Providers()` | `ProviderInterface` | Provider CRUD and idempotent ensure |
| `Services()` | `ServiceInterface` | Service exposure and management |
| `Exec()` | `ExecInterface` | Command execution (run, stream, interactive) |
| `Files()` | `FileInterface` | File upload and download |
| `Health()` | `HealthInterface` | Gateway health checking |
| `SSH()` | `SSHInterface` | SSH session and tunnel management |
| `TCP()` | `TCPInterface` | TCP port forwarding |
| `Config()` | `ConfigInterface` | Sandbox and gateway configuration |
| `Policy()` | `PolicyInterface` | Draft policy review workflow |
| `Close()` | `error` | Close the gRPC connection |

Sub-client hierarchy: `Providers()` has two nested accessors:
- `client.Providers().Profiles()` returns `ProfileInterface`
- `client.Providers().Refresh()` returns `RefreshInterface`

`Admission()` is an additive concrete-client capability. `Hold`, `Release`, `Get`
and `Receipt` require an explicit workspace, canonical sandbox name and immutable
sandbox ID. Hold/release requests retain their action IDs and expected admission
epochs across retries. Releases remove one named hold and never start compute.
Use `Get` for current state; an original historical receipt does not describe
current holds. Older gateways return `Unimplemented`; the SDK does not fall back
to a stop or policy mutation. Admission alone does not contain existing compute.

## Creating a Client

```go
import v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

client, err := v1.NewClient(v1.Config{
    Address: "gateway.example.com:443",
    Auth:    v1.StaticToken("my-token"),
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## Configuration

The `Config` struct controls connection behavior:

```go
type Config struct {
    Address     string         // Gateway address (host:port)
    TLS         *TLSConfig     // TLS settings (nil uses system defaults)
    Auth        AuthProvider   // Authentication provider
    Timeout     time.Duration  // Default timeout for all operations (0 = no timeout)
    RetryPolicy *RetryPolicy   // Retry configuration (nil = no automatic retries)
    Logger      Logger         // Custom logger (nil = no logging)
}
```

Authentication providers:
- `v1.StaticToken(token)` provides a fixed bearer token
- `v1.NoAuth()` skips authentication (for local development)

## Testing

For unit tests, use the fake client instead of a real connection:

```go
import "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"

client := fake.NewClient()
defer client.Close()
```

The fake client implements the full `ClientInterface` with in-memory stores.
See [Testing](../testing.md) for details.

See also: [Getting Started](../getting-started.md), [Architecture](../architecture.md)
