# Copyright (C) 2026 Daniele Stefano Continenza <daniele@dascos.info>
# SPDX-License-Identifier: AGPL-3.0-or-later
package RwfLogRules;

use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(parse_apache_line classify_line);

my $BAD_UA_RE = qr/(?:bytespider|babbar|barkrowler|ahrefs|semrush|mj12|seek|l9scan|leakix|zgrab|masscan|sqlmap|nikto|dirbuster|gobuster|acunetix|netsparker|python-requests|go-http-client|curl|wget|okhttp|libwww-perl|perl)/i;

sub is_bad_ua {
    my ($ua) = @_;
    $ua //= '';
    return $ua =~ $BAD_UA_RE ? 1 : 0;
}

sub parse_apache_line {
    my ($line) = @_;
    return undef unless defined $line;

    my $apache_end_us;
    $apache_end_us = 0 + $1 if $line =~ /(?:^|\s)apache_end_us=(\d+)(?:\s|$)/;

    # RwF historical format:
    # IP (vhost:port) - - [date] "METHOD URI HTTP/x" STATUS BYTES "REF" "UA"
    if ($line =~ /^(\S+)\s+\(([^)]+)\)\s+.*\[[^\]]+\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d{3})\s+\S+\s+"([^"]*)"\s+"([^"]*)"/) {
        my ($ip,$vh,$method,$uri,$proto,$status,$ref,$ua) = ($1,$2,$3,$4,$5,$6,$7,$8);
        $vh = lc($vh); $vh =~ s/:\d+$//;
        return { ip=>$ip, vhost=>$vh, method=>$method, uri=>$uri, proto=>$proto,
                 status=>$status, ref=>$ref, ua=>$ua, apache_end_us=>$apache_end_us };
    }

    # Debian/Apache vhost_combined style:
    # vhost:port IP - - [date] "METHOD URI HTTP/x" STATUS BYTES "REF" "UA"
    if ($line =~ /^(\S+?:\d+)\s+(\S+)\s+.*\[[^\]]+\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d{3})\s+\S+\s+"([^"]*)"\s+"([^"]*)"/) {
        my ($vh,$ip,$method,$uri,$proto,$status,$ref,$ua) = ($1,$2,$3,$4,$5,$6,$7,$8);
        $vh = lc($vh); $vh =~ s/:\d+$//;
        return { ip=>$ip, vhost=>$vh, method=>$method, uri=>$uri, proto=>$proto,
                 status=>$status, ref=>$ref, ua=>$ua, apache_end_us=>$apache_end_us };
    }

    return undef;
}

sub normalize_request_uri {
    my ($raw) = @_;
    $raw //= '/';
    $raw =~ s/[\r\n\t]//g;
    $raw = '/' if $raw eq '';
    $raw = "/$raw" unless $raw =~ m{^/};
    my $had_repeated = ($raw =~ m{//}) ? 1 : 0;
    my ($path) = split(/[?#]/, $raw, 2);
    return ($raw, $path, $had_repeated);
}

sub decode_uri_for_detection {
    my ($uri) = @_;
    $uri //= '/';
    my $s = $uri;
    # Detection-only decode, two passes. It does not modify Apache's URI.
    for (1..2) {
        $s =~ s/%25([0-9A-Fa-f]{2})/%$1/g;
        $s =~ s/%2[fF]/\//g;
        $s =~ s/%5[cC]/\//g;
        $s =~ s/%2[eE]/./g;
        $s =~ s/%3[fF]/?/g;
        $s =~ s/%26/&/g;
        $s =~ s/%3[dD]/=/g;
        $s =~ s/%27/'/g;
        $s =~ s/%22/"/g;
        $s =~ s/%28/(/g;
        $s =~ s/%29/)/g;
        $s =~ s/%2[cC]/,/g;
        $s =~ s/%20/ /g;
    }
    $s =~ s{//+}{/}g;
    return $s;
}

sub sql_injection_signature {
    my ($uri) = @_;
    my $s = lc(decode_uri_for_detection($uri // ''));
    $s =~ tr/+/ /;
    return 'sqli-union-select' if $s =~ /\bunion\s+(?:(?:all|distinct)\s+)?select(?:\s|\()/;
    return 'sqli-mysql-error' if $s =~ /\b(?:extractvalue|updatexml)\s*\(/;
    return '';
}

sub _match {
    my ($r, $rule, $signature, $uri) = @_;
    return {
        ip        => $r->{ip},
        rule      => $rule,
        signature => $signature,
        vhost     => $r->{vhost} || '-',
        method    => uc($r->{method} || '-'),
        raw_uri   => $r->{uri} || '/',
        uri       => $uri,
        status    => $r->{status} || '-',
        ref       => $r->{ref} // '-',
        ua        => $r->{ua} // '-',
        proto     => $r->{proto} // '-',
        apache_end_us => $r->{apache_end_us},
    };
}

sub classify_line {
    my ($line) = @_;
    my $r = parse_apache_line($line) or return undef;
    my $method = uc($r->{method} || '');
    return undef unless $method =~ /^(?:GET|POST|HEAD|OPTIONS)$/;

    my ($uri) = normalize_request_uri($r->{uri});
    my $hard_uri = decode_uri_for_detection($uri);
    my $hard_path = $hard_uri; $hard_path =~ s/[?#].*$//;
    my $status = $r->{status} // '-';
    my $ref = $r->{ref} // '-';
    my $ua = $r->{ua} // '-';

    my $sqli = sql_injection_signature($uri);
    return _match($r, $sqli, $sqli, $hard_uri) if $sqli ne '';

    if ($hard_uri =~ m{^/+wp-json/batch/v1(?:/|$|[?])}i ||
        $hard_uri =~ m{(?:\?|[&;])rest_route=/batch/v1(?:/|$|[&#;])}i) {
        return _match($r, 'wordpress-batch-v1', 'wordpress-batch-v1', $hard_uri);
    }

    return _match($r,'git-repository','git-repository-probe',$hard_uri)
        if $hard_uri =~ m{(?:^|/)[.]git(?:/|$)}i;
    return _match($r,'git-credentials','git-credentials-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]git-credentials$}i;
    return _match($r,'gitconfig','gitconfig-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]gitconfig$}i;
    return _match($r,'gitlab-ci','gitlab-ci-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]gitlab-ci[.]yml$}i;
    return _match($r,'github-workflow','github-workflow-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]github/workflows/[^/]+[.](?:yml|yaml)$}i;

    return _match($r,'env-secret','environment-secret-probe',$hard_uri)
        if $hard_uri =~ m{(?:^|/)[.]env(?:[._-][^/?#]*)?(?:/|$)}i;
    return _match($r,'vscode-sftp','vscode-sftp-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]vscode/sftp[.]json$}i;
    return _match($r,'ds-store','ds-store-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]DS_Store$}i;
    return _match($r,'wp-config-secret','wp-config-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)wp-config[.]php$}i;
    return _match($r,'aws-credentials','aws-credentials-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]aws/credentials$}i;
    return _match($r,'aws-config','aws-config-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)[.]aws/config$}i;
    return _match($r,'rclone-conf','rclone-conf-probe',$hard_uri) if lc($hard_path) eq '/rclone.conf';
    return _match($r,'rclone-hidden-conf','rclone-hidden-conf-probe',$hard_uri) if lc($hard_path) eq '/.rclone.conf';
    return _match($r,'rclone-user-conf','rclone-user-conf-probe',$hard_uri) if lc($hard_path) eq '/.config/rclone/rclone.conf';
    return _match($r,'web-config','web-config-probe',$hard_uri) if lc($hard_path) eq '/web.config';

    return _match($r,'phpunit-vendor','phpunit-vendor-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)vendor/(?:[^/]+/)*phpunit(?:/|$)}i;
    return _match($r,'phpunit-direct','phpunit-direct-probe',$hard_uri)
        if $hard_path =~ m{^/phpunit(?:/|$)}i;

    return _match($r,'known-webshell-name','known-webshell-probe',$hard_uri)
        if $hard_path =~ m{(?:^|/)(?:zwso|mah|shoha|alpha|alpa|alfa|chosen|goods|wp_filemanager|shelp|ms-themes|gifclass|txets|wp_mna|lock360|o-simple|this_is_a_new_hello_world)[.]php$}i;
    return _match($r,'known-webshell-wso','known-webshell-wso-probe',$hard_uri)
        if lc($hard_path) eq '/.wp/wso.php';
    return _match($r,'known-webshell-hellopress','known-webshell-hellopress-probe',$hard_uri)
        if $hard_path =~ m{^/wp-content/plugins/hellopress/.*[.]php$}i;

    my %exact = (
        '/wp-plain.php' => ['wordpress-wp-plain','wordpress-wp-plain'],
        '/wp-content/themes/seotheme/db.php' => ['wordpress-seotheme-db','wordpress-seotheme-db'],
        '/wp-content/plugins/apikey/apikey.php' => ['wordpress-apikey-backdoor','wordpress-apikey-backdoor'],
        '/wp-content/plugins/apikey/apikey.php.suspected' => ['wordpress-apikey-backdoor-suspected','wordpress-apikey-backdoor-suspected'],
        '/plugins/content/apismtp/apismtp.php' => ['apismtp-probe','apismtp-probe'],
        '/plugins/content/apismtp/apismtp.php.suspected' => ['apismtp-probe-suspected','apismtp-probe-suspected'],
    );
    my $lc_path = lc($hard_path);
    if (my $e = $exact{$lc_path}) { return _match($r,$e->[0],$e->[1],$hard_uri); }
    return _match($r,'alfa-perl-shell','alfa-perl-shell',$hard_uri)
        if $hard_path =~ m{(?:^|/)(?:ALFA_DATA/)?alfacgiapi/perl[.]alfa$}i;

    return _match($r,'scanner-debug-trigger','known-scanner-debug-trigger',$hard_uri)
        if $hard_path =~ m{^/z9x8c7v6b5-debug-trigger-[A-Za-z0-9._-]+(?:/|$)}i;

    # Installation-sensitive families are classified here but are OFF by
    # default in the generic configuration.
    return _match($r,'phpmyadmin-standard','phpmyadmin-standard-path-probe',$hard_uri)
        if $hard_path =~ m{^/(?:phpmyadmin|myadmin)(?:/|$)}i;
    return _match($r,'phpmyadmin-admin','phpmyadmin-admin-path-probe',$hard_uri)
        if $hard_path =~ m{^/admin/phpmyadmin(?:/|$)}i;
    return _match($r,'wordpress-xmlrpc','xmlrpc-context-probe',$hard_uri)
        if lc($hard_path) eq '/xmlrpc.php';

    # Response-context rules. These deliberately remain available only in the
    # Log Reader engine because the early Apache hook cannot know the final
    # response status/referrer context safely.
    if ($hard_path =~ m{(?:^|/)wp-login[.]php$}i &&
        $status =~ /^(?:301|302|403|404|503)$/ &&
        ($ref eq '-' || $ref eq '' || $ref =~ m{/wp-login[.]php(?:$|[?#])}i)) {
        return _match($r,'wordpress-wp-login-context','wp-login-response-context',$hard_uri);
    }

    my $is_ert = ($hard_path eq '/wp-content/plugins/easy-responsive-tabs/assets/css/ert_css.php' ||
                  $hard_path eq '/wp-content/plugins/easy-responsive-tabs/assets/js/ert_js.php') ? 1 : 0;
    my %safe_php = map { $_ => 1 } qw(index.php admin.php login.php wp-login.php xmlrpc.php wp-cron.php wp-comments-post.php wp-trackback.php wp-signup.php wp-activate.php admin-ajax.php);
    my ($basename) = $hard_path =~ m{/([^/]+)$}; $basename //= '';
    if (!$is_ert && $hard_path =~ m{^/[a-z0-9][a-z0-9_.-]{0,50}[.]php$}i &&
        !$safe_php{lc($basename)} && $status =~ /^(?:301|302|403|404|410|503)$/ &&
        ($ref eq '-' || $ref eq '') && ($ua eq '-' || $ua eq '' || is_bad_ua($ua))) {
        return _match($r,'generic-root-php-context','generic-root-php-response-context',$hard_uri);
    }

    return undef;
}

1;
