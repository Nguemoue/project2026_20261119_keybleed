# keybleed

Zero-dependency secret scanner for PHP and Laravel. **One file. No Composer. CI-friendly exit codes.**

It catches the leak that actually happens: a real `APP_KEY`, a database URL with a password, an AWS key, or a GitHub token sitting in a file that is about to be pushed.

```bash
php keybleed.php .
php keybleed.php --self-test
```

`--self-test` builds throwaway secrets in a temp directory, checks every rule, then deletes them. Nothing is sent anywhere.

## Why this exists

Laravel projects keep production credentials in `.env`. One bad commit and `APP_KEY`, `DB_PASSWORD`, Stripe, OpenAI or AWS are public. Heavy scanners are great, but most of them need Node, Python, or a vendor directory. keybleed is a single PHP file you can drop into a repo or a pre-commit hook in thirty seconds.

## Detects

| Rule | Severity | What |
| --- | --- | --- |
| `laravel_app_key` | critical | `APP_KEY=base64:…` |
| `aws_access_key` / `aws_temp_key` | critical | `AKIA…` / `ASIA…` access key ids |
| `github_pat` / `github_oauth` / `github_fine` | critical | GitHub personal, OAuth, and fine-grained tokens |
| `gitlab_pat` | critical | GitLab personal tokens |
| `stripe_live` | critical | Live Stripe secret keys |
| `stripe_test` | medium | Stripe test keys |
| `slack_token` / `slack_webhook` | critical | Bot tokens and incoming webhooks |
| `openai` / `anthropic` | critical | `sk-proj-…` and `sk-ant-…` |
| `google_api` | high | Google API keys |
| `sendgrid` / `npm_token` / `shopify` / `digitalocean` | critical | Provider tokens |
| `huggingface` | high | Hugging Face tokens |
| `private_key` | critical | PEM private key blocks |
| `db_url` | critical | `mysql://`, `postgres://`, `mongodb://`, `redis://`, `amqp://` with a password |
| `generic_secret` | high | Assigned `*_SECRET`, `*_PASSWORD`, `*_TOKEN`, `API_KEY`, `APP_KEY`, … |
| `jwt` | medium | JSON Web Tokens |

Placeholders (`password`, `changeme`, `your_…`, `example`, empty values, paths) are ignored. The documented AWS example access key id is ignored too. `vendor/`, `node_modules/`, `.git/`, `storage/framework/`, `storage/logs/`, and `bootstrap/cache/` are skipped.

## Use it

Scan the current directory (exit `1` if something high or critical is found):

```bash
php keybleed.php
```

Machine-readable output, for CI logs:

```bash
php keybleed.php --json --fail-on=high
```

Only the files sitting in the git index (pre-commit):

```bash
php keybleed.php --staged
```

Thresholds: `low`, `medium`, `high` (default), `critical`.

### GitHub Actions

```yaml
- uses: shivammathur/setup-php@v2
  with:
    php-version: '8.3'
- run: php keybleed.php --self-test
- run: php keybleed.php . --fail-on=high
```

### Pre-commit

```bash
git config core.hooksPath .githooks
```

The hook in this repo runs `php keybleed.php --staged`.

## Silence a false positive

Put `keybleed-ignore` on the same line:

```php
$fixture = 'not-a-real-value'; // keybleed-ignore
```

Or list paths in `.keybleedignore` (prefix or glob, `#` comments):

```gitignore
ignored/
*.min.js
storage/app/private/
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Nothing at or above the threshold |
| 1 | Secrets found |
| 2 | Bad usage, or the path cannot be scanned |

JSON goes to stdout and never includes the raw secret, only a redacted preview. Human output is redacted the same way.

## Requirements

PHP 8.1 or newer. No extensions beyond the standard CLI build. Works as a single file: you do not need the rest of this repository.

```bash
curl -fsSL -o keybleed.php https://raw.githubusercontent.com/Nguemoue/project2026_20261119_keybleed/main/keybleed.php
php keybleed.php --self-test
```

## Limits

keybleed is a fast local gate, not a full secret-management program. It will miss custom formats it does not know, and it can still miss a secret that looks like a placeholder. Pair it with GitHub push protection or a server-side scanner if you need that net too. It does not upload code or open a network connection.

## Français

keybleed est un scanner de secrets **sans dépendance** pour PHP et Laravel. Un seul fichier, pas de Composer.

Il vise le vrai accident : un `.env` (ou un dump de chat) qui part sur Git avec un `APP_KEY`, un mot de passe de base, une clé AWS, Stripe, OpenAI ou un token GitHub.

```bash
php keybleed.php .
php keybleed.php --self-test   # fixtures jetables, puis suppression
php keybleed.php --staged      # uniquement les fichiers dans l'index git
```

Le code de sortie `1` casse une CI ou un hook de pre-commit. `--json` donne un rapport sans la valeur brute du secret. Les faux positifs se taisent avec `keybleed-ignore` sur la ligne, ou avec `.keybleedignore`.

## License

MIT. See [LICENSE](LICENSE).
