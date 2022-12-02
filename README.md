# hmacproxy HMAC authentication proxy server

This verifies requests have a valid hmac signature and if they do proxies them to the 
appropriate server.

This is intended for handling GitHub webhooks. The intention is to have a single loadbalancer
that forwards all webhooks to the proxy which validates the request and then proxies them to the actual
GitHub App. This approach gives us an extra layer of security which ensures we don't wholly rely on individual
GitHub Apps authenticating the webhooks. Individual apps should still validate webhooks for added security.

The proxy is configured with a YAML like the one below

```yaml
routes:
  - path: "/api/github/annotate/webhook"
    upstream: "http://localhost:80/api/github/webhook"
```

A request must exactly match the path in order to be proxied to the target location.

## Curl Support

CLI supports issuing a signed request which is useful for testing/development.

```
curl --secret-file="gcpSecretManager:///projects/yourproject/secrets/github-webhook/versions/latest" --url=https://webhooks.yourdomain.dev/path
```
## References

Originally forked from [18f/hmacauth](https://github.com/18F/hmacauth)