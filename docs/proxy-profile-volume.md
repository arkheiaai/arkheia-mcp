# Proxy profile volume

Compose gives the proxy its existing `profile_data` named volume at
`/app/profiles`, the path selected by the image's `ARKHEIA_PROFILES_DIR`.
The registry server still reads `./profiles` through its read-only bind.
The proxy does not update that host source.

The image includes bundled profiles at the mount destination. Docker normally
populates an empty named volume from the image on container creation; a nonempty
volume retains its existing files. Updating the image or the host `profiles/`
directory does not replace an existing populated proxy volume. Use the registry
update path or intentional operator provisioning for those files.

Before any cutover, verify the actual volume's ownership and write access as the
image's non-root user, and authenticate the full expected per-model inventory for
that deployment. Check fresh-volume initialization, an actual registry update,
restart persistence, and that the registry source remains unchanged. These
Docker integration checks were not established by the offline config tests.
Do not proceed without that inventory and permission evidence.

Health 200 alone is insufficient. With `ARKHEIA_REQUIRE_LICENSE=true`, zero valid
profiles refuses startup. With its default false setting, startup can continue
with UNKNOWN detections and health can report `ok` despite zero profiles. This
volume correction does not change licensing, UNKNOWN or health policy.

To roll back, stop the proxy and restore the previous Compose configuration
while preserving `profile_data` and all pending updates. Do not delete or prune
the volume. Inspect and reconcile any intentionally provisioned data before
another cutover; never overwrite preserved profiles automatically.
