#!/usr/bin/env bash
# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
# Shared platform helpers for the RwF installer/self-test/rollback scripts.
# shellcheck shell=bash

rwf_detect_platform() {
    local id="" id_like=""

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        id="${ID:-}"
        id_like="${ID_LIKE:-}"
    fi

    RWF_DISTRO_ID="$id"
    RWF_DISTRO_FAMILY=""

    case " $id $id_like " in
        *" debian "*|*" ubuntu "*) RWF_DISTRO_FAMILY="debian" ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) RWF_DISTRO_FAMILY="rhel" ;;
        *" suse "*|*" opensuse "*|*" sles "*) RWF_DISTRO_FAMILY="suse" ;;
    esac

    if [[ -z "$RWF_DISTRO_FAMILY" ]]; then
        if command -v apt-get >/dev/null 2>&1 && [[ -d /etc/apache2 ]]; then
            RWF_DISTRO_FAMILY="debian"
        elif { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; } && [[ -d /etc/httpd ]]; then
            RWF_DISTRO_FAMILY="rhel"
        elif command -v zypper >/dev/null 2>&1 && [[ -d /etc/apache2 ]]; then
            RWF_DISTRO_FAMILY="suse"
        fi
    fi

    case "$RWF_DISTRO_FAMILY" in
        debian)
            RWF_APACHE_ETC="/etc/apache2"
            RWF_APACHE_SERVICE="apache2"
            RWF_APACHE_CTL="$(command -v apache2ctl || command -v apachectl || true)"
            RWF_APACHE_STYLE="debian"
            RWF_APACHE_GROUP="www-data"
            if [[ -r /etc/apache2/envvars ]]; then
                set +u
                # shellcheck disable=SC1091
                source /etc/apache2/envvars
                set -u
                RWF_APACHE_GROUP="${APACHE_RUN_GROUP:-www-data}"
            fi
            RWF_PACKAGE_MANAGER="apt"
            ;;

        rhel)
            RWF_APACHE_ETC="/etc/httpd"
            RWF_APACHE_SERVICE="httpd"
            RWF_APACHE_CTL="$(command -v apachectl || command -v httpd || true)"
            RWF_APACHE_STYLE="direct"
            RWF_APACHE_GROUP="apache"
            RWF_PACKAGE_MANAGER="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)"
            ;;

        suse)
            RWF_APACHE_ETC="/etc/apache2"
            RWF_APACHE_SERVICE="apache2"
            RWF_APACHE_CTL="$(command -v apache2ctl || command -v apachectl || command -v httpd2 || true)"
            RWF_APACHE_STYLE="direct"
            if getent group www >/dev/null 2>&1; then
                RWF_APACHE_GROUP="www"
            elif getent group www-data >/dev/null 2>&1; then
                RWF_APACHE_GROUP="www-data"
            else
                RWF_APACHE_GROUP="www"
            fi
            RWF_PACKAGE_MANAGER="zypper"
            ;;

        *) return 1 ;;
    esac

    return 0
}

rwf_apache_configtest() {
    "$RWF_APACHE_CTL" configtest 2>/dev/null || "$RWF_APACHE_CTL" -t
}

rwf_apache_reload() {
    systemctl reload "$RWF_APACHE_SERVICE"
}

rwf_apache_module_list() {
    "$RWF_APACHE_CTL" -M 2>/dev/null
}

# Avoid producer | grep -q under pipefail: the producer may receive SIGPIPE.
rwf_apache_module_loaded() {
    local modules
    modules="$(rwf_apache_module_list)" || return 1
    grep -F 'rwf_module (shared)' <<<"$modules" >/dev/null
}

rwf_apache_enable() {
    case "$RWF_APACHE_STYLE" in
        debian)
            a2enmod rwf >/dev/null
            a2enconf reactive-web-firewall-log >/dev/null
            ;;
        direct)
            ;;
    esac
}

rwf_apache_disable() {
    case "$RWF_APACHE_STYLE" in
        debian)
            a2dismod rwf >/dev/null 2>&1 || true
            a2disconf reactive-web-firewall-log >/dev/null 2>&1 || true
            ;;
        direct)
            local p
            for p in "${RWF_LOAD_FILE:-}" "${RWF_CONF_FILE:-}" "${RWF_LOG_CONF_FILE:-}"; do
                [[ -n "$p" && -e "$p" ]] || continue
                mv -f -- "$p" "$p.rwf-disabled"
            done
            ;;
    esac
}

rwf_apache_paths() {
    local module_dir="$1"

    case "$RWF_APACHE_STYLE:$RWF_DISTRO_FAMILY" in
        debian:debian)
            RWF_LOAD_FILE="$RWF_APACHE_ETC/mods-available/rwf.load"
            RWF_CONF_FILE="$RWF_APACHE_ETC/mods-available/rwf.conf"
            RWF_LOG_CONF_FILE="$RWF_APACHE_ETC/conf-available/reactive-web-firewall-log.conf"
            RWF_ENABLED_CONF_DISPLAY="$RWF_APACHE_ETC/mods-enabled/rwf.conf"
            RWF_ENABLED_LOG_DISPLAY="$RWF_APACHE_ETC/conf-enabled/reactive-web-firewall-log.conf"
            ;;
        direct:rhel)
            RWF_LOAD_FILE="$RWF_APACHE_ETC/conf.modules.d/30-rwf.conf"
            RWF_CONF_FILE="$RWF_APACHE_ETC/conf.d/reactive-web-firewall.conf"
            RWF_LOG_CONF_FILE="$RWF_APACHE_ETC/conf.d/reactive-web-firewall-log.conf"
            RWF_ENABLED_CONF_DISPLAY="$RWF_CONF_FILE"
            RWF_ENABLED_LOG_DISPLAY="$RWF_LOG_CONF_FILE"
            ;;
        direct:suse)
            RWF_LOAD_FILE="$RWF_APACHE_ETC/conf.d/30-rwf-load.conf"
            RWF_CONF_FILE="$RWF_APACHE_ETC/conf.d/reactive-web-firewall.conf"
            RWF_LOG_CONF_FILE="$RWF_APACHE_ETC/conf.d/reactive-web-firewall-log.conf"
            RWF_ENABLED_CONF_DISPLAY="$RWF_CONF_FILE"
            RWF_ENABLED_LOG_DISPLAY="$RWF_LOG_CONF_FILE"
            ;;
        *) return 1 ;;
    esac

    RWF_MODULE_FILE="$module_dir/mod_rwf.so"
}

rwf_package_is_installed() {
    local pkg="$1"
    case "$RWF_PACKAGE_MANAGER" in
        apt)
            local status
            status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null)" || return 1
            grep -F 'install ok installed' <<<"$status" >/dev/null
            ;;
        dnf|yum|zypper)
            rpm -q "$pkg" >/dev/null 2>&1
            ;;
        *) return 1 ;;
    esac
}

rwf_install_packages() {
    case "$RWF_PACKAGE_MANAGER" in
        apt)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf)
            dnf install -y "$@"
            ;;
        yum)
            yum install -y "$@"
            ;;
        zypper)
            zypper --non-interactive install "$@"
            ;;
        *) return 1 ;;
    esac
}

# Base packages. The Log Reader still compiles the small privileged helper,
# but it does not require Apache development headers/APXS.
rwf_required_packages() {
    local engine="${1:-inside-apache}"
    case "$RWF_DISTRO_FAMILY:$engine" in
        debian:inside-apache) printf '%s\n' apache2 apache2-dev build-essential iproute2 nftables curl python3 perl util-linux ;;
        debian:log-reader)    printf '%s\n' apache2 build-essential iproute2 nftables curl python3 perl util-linux ;;
        rhel:inside-apache)   printf '%s\n' httpd httpd-devel gcc make libtool iproute nftables curl python3 perl util-linux ;;
        rhel:log-reader)      printf '%s\n' httpd gcc make libtool iproute nftables curl python3 perl util-linux ;;
        suse:inside-apache)   printf '%s\n' apache2 apache2-devel gcc make libtool iproute2 nftables curl python3 perl util-linux ;;
        suse:log-reader)      printf '%s\n' apache2 gcc make libtool iproute2 nftables curl python3 perl util-linux ;;
    esac
}

rwf_default_module_dir() {
    case "$RWF_DISTRO_FAMILY" in
        debian) printf '%s\n' /usr/lib/apache2/modules ;;
        rhel)
            [[ -d /usr/lib64/httpd/modules ]] && printf '%s\n' /usr/lib64/httpd/modules || printf '%s\n' /usr/lib/httpd/modules
            ;;
        suse)
            [[ -d /usr/lib64/apache2 ]] && printf '%s\n' /usr/lib64/apache2 || printf '%s\n' /usr/lib/apache2
            ;;
    esac
}

# Additional package required only when the remote OpenWrt backend is selected.
rwf_openwrt_packages() {
    case "$RWF_DISTRO_FAMILY" in
        debian) printf '%s\n' openssh-client ;;
        rhel)   printf '%s\n' openssh-clients ;;
        suse)   printf '%s\n' openssh ;;
    esac
}
