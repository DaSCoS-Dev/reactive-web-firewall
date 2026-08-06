# Immediate rules

| Regola | Default | Esempi |
|---|---:|---|
| `git_exploit` | permanent | `/.git/config`, `/app/.git/HEAD` |
| `env_exploit` | permanent | `/.env`, `/wp-config.php`, `/.aws/credentials` |
| `framework_exploit` | permanent | probe PHPUnit |
| `xmlrpc` | 3 days | `/xmlrpc.php` |
| `wp_batch` | 3 days | `/wp-json/batch/v1` |
| `sql_injection` | 2 weeks | union-select, time-based, stacked query |
| `known_webshell` | permanent | nomi di webshell conosciuti |
| `php_probe` | 1 hour | file PHP radice sospetti con status/referrer/UA restrittivi |
| `wp_login` | 4 hours | probe login con status e referrer restrittivi |

Do not add ambiguous signatures to the immediate path. Use slower threshold or reputation systems for broader detection.
