# Optional CSF/LFD integration

Reactive Web Firewall does not require CSF. When LFD parses the same Apache log,
it may process lines already queued after the immediate ban and apply a second,
different-duration ban.

Merge `immediate-ban-marker-snippet.pm` into the existing `regex.custom.pm` and,
after extracting the source address, use:

```perl
return 0 if rwf_immediate_ban_active($ip);
```

Do not blindly replace an existing CSF custom regex file. It is normally
installation-specific and must be merged manually.
