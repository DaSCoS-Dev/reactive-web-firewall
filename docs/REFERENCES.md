# Technical references

Primary documentation used for the public distribution:

- Apache HTTP Server 2.4 log documentation: https://httpd.apache.org/docs/2.4/logs.html
- Apache `mod_log_config` and `GlobalLog`: https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
- Apache `mod_logio`: https://httpd.apache.org/docs/2.4/mod/mod_logio.html
- OpenWrt releases: https://github.com/openwrt/openwrt/releases
- OpenWrt Dropbear configuration: https://openwrt.org/docs/guide-user/base-system/dropbear
- Debian package index: https://packages.debian.org/

`GlobalLog` requires Apache 2.4.19 or later and records requests for virtual hosts that define their own `CustomLog`.
