# Regole immediate

| Regola | Predefinita | Esempi |
|---|---:|---|
| `git_exploit` | permanente | `/.git/config`, `/app/.git/HEAD` |
| `env_exploit` | permanente | `/.env`, `/wp-config.php`, `/.aws/credentials` |
| `framework_exploit` | permanente | probe PHPUnit |
| `xmlrpc` | 3 giorni | `/xmlrpc.php` |
| `wp_batch` | 3 giorni | `/wp-json/batch/v1` |
| `sql_injection` | 2 settimane | union-select, time-based, stacked query |
| `known_webshell` | permanente | nomi di webshell conosciuti |
| `php_probe` | 1 ora | file PHP radice sospetti con status/referrer/UA restrittivi |
| `wp_login` | 4 ore | probe login con status e referrer restrittivi |

Non aggiungere firme ambigue al percorso immediato. Per soglie, reputazione o campagne distribuite usare strumenti separati e più lenti.
