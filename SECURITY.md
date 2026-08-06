# Security policy

Report vulnerabilities privately before opening a public issue when exploitation details could endanger installations.

The installer creates a dedicated SSH key. The corresponding OpenWrt entry is forced to `reactive-fw-dispatch` and disables PTY and forwarding. Keep the firewall SSH service restricted to management networks and verify the displayed host-key fingerprint.

Never publish private keys, `authorized_keys`, production blocklists, packet captures, real client logs or site-specific Apache VirtualHosts when reporting a problem.
