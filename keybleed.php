#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * keybleed — zero-dependency secret scanner for PHP / Laravel trees.
 *
 *   php keybleed.php [path] [--json] [--staged] [--fail-on=high]
 *   php keybleed.php --self-test
 */

const KB_VERSION = '1.0.0';

const KB_SEVERITY = [
    'low' => 1,
    'medium' => 2,
    'high' => 3,
    'critical' => 4,
];

const KB_SKIP_DIRS = [
    'vendor',
    'node_modules',
    '.git',
    'coverage',
    'dist',
    '.idea',
    '.phpunit.cache',
];

const KB_SKIP_EXT = [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg',
    'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'gz', 'tgz',
    'phar', 'exe', 'so', 'dll', 'wasm', 'mp4', 'mp3', 'lock',
    'pack', 'idx',
];

/** @var list<array{0:string,1:string,2:string}> id, severity, regex */
const KB_RULES = [
    ['aws_access_key', 'critical', '/\b(AKIA[0-9A-Z]{16})\b/'],
    ['aws_temp_key', 'critical', '/\b(ASIA[0-9A-Z]{16})\b/'],
    ['github_pat', 'critical', '/\b(ghp_[A-Za-z0-9]{36})\b/'],
    ['github_oauth', 'critical', '/\b(gho_[A-Za-z0-9]{36})\b/'],
    ['github_fine', 'critical', '/\b(github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/'],
    ['gitlab_pat', 'critical', '/\b(glpat-[A-Za-z0-9_\-]{20,})\b/'],
    ['stripe_live', 'critical', '/\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/'],
    ['stripe_test', 'medium', '/\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b/'],
    ['slack_token', 'critical', '/\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/'],
    ['slack_webhook', 'critical', '#(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,})#'],
    ['openai', 'critical', '/\b(sk-proj-[A-Za-z0-9_\-]{20,})\b/'],
    ['anthropic', 'critical', '/\b(sk-ant-[A-Za-z0-9_\-]{20,})\b/'],
    ['google_api', 'high', '/\b(AIza[0-9A-Za-z\-_]{35})\b/'],
    ['sendgrid', 'critical', '/\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b/'],
    ['npm_token', 'critical', '/\b(npm_[A-Za-z0-9]{36})\b/'],
    ['huggingface', 'high', '/\b(hf_[A-Za-z0-9]{30,})\b/'],
    ['digitalocean', 'critical', '/\b(dop_v1_[a-f0-9]{64})\b/'],
    ['shopify', 'critical', '/\b(shpca_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32})\b/'],
    ['private_key', 'critical', '/(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/'],
    ['laravel_app_key', 'critical', '/\b(base64:[A-Za-z0-9+\/=]{40,})\b/'],
    ['jwt', 'medium', '/\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/'],
];

function kb_main(array $argv): int
{
    $opts = kb_parse_args($argv);
    if ($opts['error'] !== null) {
        fwrite(STDERR, "keybleed: {$opts['error']}\n");
        fwrite(STDERR, kb_help());
        return 2;
    }
    if ($opts['help']) {
        fwrite(STDOUT, kb_help());
        return 0;
    }
    if ($opts['version']) {
        fwrite(STDOUT, KB_VERSION . "\n");
        return 0;
    }
    if ($opts['self_test']) {
        return kb_self_test();
    }

    try {
        $report = kb_run_scan($opts['path'], $opts['staged']);
    } catch (RuntimeException $e) {
        fwrite(STDERR, "keybleed: {$e->getMessage()}\n");
        return 2;
    }

    $hit = kb_above($report['findings'], $opts['fail_on']);
    $report['ok'] = $hit === [];
    $report['fail_on'] = $opts['fail_on'];

    if ($opts['json']) {
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        fwrite(STDOUT, ($json === false ? "{}\n" : $json . "\n"));
    } else {
        kb_render($report, $opts['color'], $opts['fail_on']);
    }

    return $hit === [] ? 0 : 1;
}

/** @param list<string> $argv */
function kb_parse_args(array $argv): array
{
    $opts = [
        'path' => null,
        'json' => false,
        'staged' => false,
        'self_test' => false,
        'help' => false,
        'version' => false,
        'color' => true,
        'fail_on' => 'high',
        'error' => null,
    ];

    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--json') {
            $opts['json'] = true;
        } elseif ($arg === '--staged') {
            $opts['staged'] = true;
        } elseif ($arg === '--self-test') {
            $opts['self_test'] = true;
        } elseif ($arg === '--no-color') {
            $opts['color'] = false;
        } elseif ($arg === '--help' || $arg === '-h') {
            $opts['help'] = true;
        } elseif ($arg === '--version' || $arg === '-V') {
            $opts['version'] = true;
        } elseif (str_starts_with($arg, '--fail-on=')) {
            $level = substr($arg, strlen('--fail-on='));
            if (!isset(KB_SEVERITY[$level])) {
                $opts['error'] = "unknown severity '{$level}' (use low, medium, high, critical)";
                return $opts;
            }
            $opts['fail_on'] = $level;
        } elseif (str_starts_with($arg, '-')) {
            $opts['error'] = "unknown option {$arg}";
            return $opts;
        } elseif ($opts['path'] !== null) {
            $opts['error'] = 'only one path is accepted';
            return $opts;
        } else {
            $opts['path'] = $arg;
        }
    }

    if ($opts['color'] && (getenv('NO_COLOR') !== false && getenv('NO_COLOR') !== '')) {
        $opts['color'] = false;
    }
    if ($opts['color'] && function_exists('stream_isatty')) {
        $opts['color'] = stream_isatty(STDOUT);
    }

    return $opts;
}

function kb_help(): string
{
    $v = KB_VERSION;
    return <<<TXT
keybleed {$v} — catch leaked secrets in PHP / Laravel projects

Usage:
  php keybleed.php [path] [--json] [--staged] [--fail-on=LEVEL] [--no-color]
  php keybleed.php --self-test

Options:
  path              File or directory to scan (default: current directory)
  --staged          Scan files in the git index only (pre-commit)
  --json            Machine-readable report on stdout
  --fail-on=LEVEL   Exit 1 at this severity or above (default: high)
  --no-color        Disable ANSI colors
  --self-test       Generate throwaway fixtures, scan them, delete them
  -h, --help        Show this help
  -V, --version     Print version

Exit codes:
  0  nothing at or above the threshold
  1  secrets found
  2  bad usage, or the path cannot be scanned

A line containing "keybleed-ignore" is skipped. Patterns also live in
.keybleedignore (prefix or glob), next to the scanned root.

TXT;
}

function kb_run_scan(?string $path, bool $staged): array
{
    $start = $path ?? getcwd();
    if ($start === false || $start === '') {
        throw new RuntimeException('cannot resolve the working directory');
    }
    if (!file_exists($start)) {
        throw new RuntimeException("path not found: {$start}");
    }

    if ($staged) {
        $root = kb_git_root($start);
        if ($root === null) {
            throw new RuntimeException('not a git repository (needed for --staged)');
        }
        $files = kb_staged_files($root);
        $base = $root;
    } else {
        [$base, $files] = kb_collect_files($start);
    }

    $ignore = kb_load_ignore($base);
    return kb_scan_files($files, $base, $ignore);
}

/** @param list<string> $files @param list<string> $ignore */
function kb_scan_files(array $files, string $base, array $ignore): array
{
    $started = microtime(true);
    $findings = [];
    $scanned = 0;

    foreach ($files as $file) {
        if (!is_file($file) || !is_readable($file)) {
            continue;
        }
        $rel = kb_rel($base, $file);
        if (kb_ignored_rel($rel, $ignore)) {
            continue;
        }
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if ($ext !== '' && in_array($ext, KB_SKIP_EXT, true)) {
            continue;
        }
        $raw = file_get_contents($file);
        if ($raw === false || strlen($raw) > 1_000_000) {
            continue;
        }
        if (str_contains(substr($raw, 0, 8192), "\0")) {
            continue;
        }
        $scanned++;
        $lines = preg_split("/\r\n|\n|\r/", $raw) ?: [];
        $n = 0;
        foreach ($lines as $line) {
            $n++;
            if (strlen($line) > 2000) {
                continue;
            }
            foreach (kb_analyze_line($line) as $hit) {
                $findings[] = [
                    'rule' => $hit['rule'],
                    'severity' => $hit['severity'],
                    'file' => $rel,
                    'line' => $n,
                    'redacted' => $hit['redacted'],
                ];
            }
        }
    }

    usort($findings, static function (array $a, array $b): int {
        return [$a['file'], $a['line'], $a['rule']] <=> [$b['file'], $b['line'], $b['rule']];
    });

    return [
        'tool' => 'keybleed',
        'version' => KB_VERSION,
        'files_scanned' => $scanned,
        'duration_ms' => (int) round((microtime(true) - $started) * 1000),
        'findings' => $findings,
    ];
}

/** @return list<array{rule:string,severity:string,redacted:string}> */
function kb_analyze_line(string $line): array
{
    if (stripos($line, 'keybleed-ignore') !== false) {
        return [];
    }

    $hits = [];
    $seen = [];

    foreach (KB_RULES as [$id, $severity, $regex]) {
        if (!preg_match_all($regex, $line, $matches, PREG_SET_ORDER)) {
            continue;
        }
        foreach ($matches as $m) {
            $secret = $m[1];
            if (kb_is_known_dummy($secret) || kb_is_placeholder($secret)) {
                continue;
            }
            if ($id === 'laravel_app_key' && kb_is_placeholder(substr($secret, strlen('base64:')))) {
                continue;
            }
            $key = $id . "\0" . $secret;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $hits[] = [
                'rule' => $id,
                'severity' => $severity,
                'redacted' => kb_redact($secret, $id),
            ];
        }
    }

    if (preg_match('#\b((?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://([^:\s\'"<>]*):([^@\s\'"<>]+)@[^\s\'"<>]+)#i', $line, $db)) {
        if (!kb_is_placeholder($db[3]) && !kb_is_known_dummy($db[1])) {
            $hits[] = [
                'rule' => 'db_url',
                'severity' => 'critical',
                'redacted' => kb_redact($db[1], 'db_url'),
            ];
        }
    }

    if ($hits === []) {
        $generic = kb_match_generic($line);
        if ($generic !== null) {
            $hits[] = [
                'rule' => 'generic_secret',
                'severity' => 'high',
                'redacted' => kb_redact($generic, 'generic_secret'),
            ];
        }
    }

    return $hits;
}

function kb_match_generic(string $line): ?string
{
    $trim = trim($line);
    if (!preg_match('/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/', $trim, $m)) {
        return null;
    }
    $name = strtoupper($m[1]);
    $hot = $name === 'APP_KEY'
        || str_contains($name, 'SECRET')
        || str_contains($name, 'PASSWORD')
        || str_contains($name, 'PASSWD')
        || str_contains($name, 'TOKEN')
        || str_contains($name, 'API_KEY')
        || str_contains($name, 'ACCESS_KEY')
        || str_contains($name, 'CLIENT_SECRET');
    if (!$hot) {
        return null;
    }
    $value = kb_parse_value($m[2]);
    if (strlen($value) < 8 || kb_is_placeholder($value)) {
        return null;
    }
    if (preg_match('#^(https?://|/|~?/|\./|\.\./)#', $value) && !preg_match('#[a-z][a-z0-9+\-.]*://[^:\s]+:[^@\s]+@#i', $value)) {
        return null;
    }
    if (str_starts_with($value, '$') || str_starts_with($value, 'env(') || str_starts_with($value, 'getenv(')) {
        return null;
    }
    return $value;
}

function kb_parse_value(string $raw): string
{
    $raw = trim($raw);
    if ($raw === '') {
        return '';
    }
    $quote = $raw[0];
    if (($quote === '"' || $quote === "'") && str_contains(substr($raw, 1), $quote)) {
        $end = strpos($raw, $quote, 1);
        if ($end !== false) {
            return substr($raw, 1, $end - 1);
        }
    }
    $raw = preg_replace('/\s+#.*$/', '', $raw) ?? $raw;
    return trim($raw, " \t\"'");
}

function kb_is_placeholder(string $value): bool
{
    $v = trim($value);
    if ($v === '') {
        return true;
    }
    $lower = strtolower($v);
    $exact = [
        'changeme', 'change_me', 'change-me', 'secret', 'password', 'passwd',
        'token', 'null', 'none', 'undefined', 'example', 'dummy', 'sample',
        'fake', 'redacted', 'test', 'testing', 'todo', 'fixme', 'replace_me',
        'replaceme', 'your_secret', 'xxx', 'xxxx', 'xxxxx', '123456',
        '12345678', 'password123', 'admin', 'root', 'qwerty', 'somerandomstring',
        'true', 'false', 'yes', 'no', 'foo', 'bar', 'secret123', 'password1',
        'pass', 'passw0rd', 'default', 'n/a', 'na', 'nil', 'empty', 'void',
        '****', '*****', 'your_password', 'your-password', 'your_api_key',
        'base64:', 'insert', 'placeholder',
    ];
    if (in_array($lower, $exact, true)) {
        return true;
    }
    foreach (['example', 'placeholder', 'changeme', 'xxxx', 'your_key', 'your-key', 'insert_here', 'replace_me', 'somerandom'] as $needle) {
        if (str_contains($lower, $needle)) {
            return true;
        }
    }
    if (str_starts_with($lower, 'your_') || str_starts_with($lower, 'your-')
        || str_starts_with($v, '<') || str_starts_with($v, '${') || str_starts_with($v, '{{')
        || str_starts_with($lower, 'dummy') || str_starts_with($lower, 'fake_')
        || str_starts_with($lower, 'sample_') || str_starts_with($lower, 'todo')) {
        return true;
    }
    if (preg_match('/^(.)\1{7,}$/', $v) === 1) {
        return true;
    }
    if (preg_match('/^[0-9]+$/', $v) === 1 && strlen($v) < 16) {
        return true;
    }
    return false;
}

function kb_is_known_dummy(string $secret): bool
{
    static $dummies = null;
    if ($dummies === null) {
        $dummies = [
            'AKIA' . 'IOSFODNN7EXAMPLE',
            'ASIA' . 'IOSFODNN7EXAMPLE',
        ];
    }
    return in_array($secret, $dummies, true);
}

function kb_redact(string $secret, string $rule): string
{
    if ($rule === 'private_key') {
        return '[PRIVATE KEY]';
    }
    if ($rule === 'db_url') {
        $redacted = preg_replace('#://([^:/@]*):([^@]+)@#', '://$1:••••@', $secret);
        return $redacted === null ? '[DB URL]' : $redacted;
    }
    $len = strlen($secret);
    if ($len <= 8) {
        return str_repeat('•', $len);
    }
    return substr($secret, 0, 4) . '••••' . substr($secret, -2);
}

/** @return array{0:string,1:list<string>} */
function kb_collect_files(string $start): array
{
    $start = realpath($start) ?: $start;
    if (is_file($start)) {
        return [dirname($start), [$start]];
    }
    if (!is_dir($start)) {
        throw new RuntimeException("not a file or directory: {$start}");
    }

    $dir = new RecursiveDirectoryIterator($start, FilesystemIterator::SKIP_DOTS);
    $filter = new RecursiveCallbackFilterIterator(
        $dir,
        static function (SplFileInfo $current): bool {
            if ($current->isDir() && in_array($current->getFilename(), KB_SKIP_DIRS, true)) {
                return false;
            }
            return true;
        }
    );
    $it = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY);
    $files = [];
    foreach ($it as $file) {
        if ($file->isFile()) {
            $files[] = $file->getPathname();
        }
    }
    return [$start, $files];
}

/** @param list<string> $ignore */
function kb_ignored_rel(string $rel, array $ignore): bool
{
    $rel = str_replace('\\', '/', $rel);
    $parts = explode('/', $rel);
    $last = count($parts) - 1;
    foreach ($parts as $i => $part) {
        if ($i === $last) {
            break;
        }
        if (in_array($part, KB_SKIP_DIRS, true)) {
            return true;
        }
    }
    foreach (['storage/framework/', 'storage/logs/', 'bootstrap/cache/', 'public/build/'] as $prefix) {
        if (str_contains($rel, $prefix)) {
            return true;
        }
    }
    foreach ($ignore as $rule) {
        $rule = str_replace('\\', '/', $rule);
        if (str_contains($rule, '*') || str_contains($rule, '?')) {
            if (fnmatch($rule, $rel, FNM_PATHNAME) || fnmatch($rule, basename($rel))) {
                return true;
            }
            continue;
        }
        $rule = rtrim($rule, '/');
        if ($rel === $rule || str_starts_with($rel, $rule . '/')) {
            return true;
        }
    }
    return false;
}

/** @return list<string> */
function kb_load_ignore(string $root): array
{
    $file = rtrim($root, '/') . '/.keybleedignore';
    if (!is_file($file)) {
        return [];
    }
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return [];
    }
    $rules = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $rules[] = $line;
    }
    return $rules;
}

function kb_rel(string $base, string $path): string
{
    $base = rtrim(str_replace('\\', '/', $base), '/');
    $path = str_replace('\\', '/', $path);
    if (str_starts_with($path, $base . '/')) {
        return substr($path, strlen($base) + 1);
    }
    return basename($path);
}

function kb_git_root(string $start): ?string
{
    $dir = is_dir($start) ? $start : dirname($start);
    $out = [];
    exec('git -C ' . escapeshellarg($dir) . ' rev-parse --show-toplevel 2>/dev/null', $out, $code);
    if ($code !== 0 || !isset($out[0]) || $out[0] === '') {
        return null;
    }
    return $out[0];
}

/** @return list<string> */
function kb_staged_files(string $root): array
{
    $raw = shell_exec('git -C ' . escapeshellarg($root) . ' diff --cached --name-only -z --diff-filter=ACMR 2>/dev/null');
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $files = [];
    foreach (explode("\0", $raw) as $rel) {
        if ($rel === '') {
            continue;
        }
        $abs = $root . '/' . $rel;
        if (is_file($abs)) {
            $files[] = $abs;
        }
    }
    return $files;
}

/** @param list<array{severity:string}> $findings @return list<array{severity:string}> */
function kb_above(array $findings, string $failOn): array
{
    $min = KB_SEVERITY[$failOn];
    return array_values(array_filter(
        $findings,
        static fn (array $f): bool => KB_SEVERITY[$f['severity']] >= $min
    ));
}

function kb_render(array $report, bool $color, string $failOn): void
{
    $reset = $color ? "\033[0m" : '';
    $bold = $color ? "\033[1m" : '';
    $dim = $color ? "\033[2m" : '';
    $green = $color ? "\033[32m" : '';

    $findings = $report['findings'];
    if ($findings === []) {
        fwrite(STDOUT, "{$green}keybleed:{$reset} no secrets found {$dim}({$report['files_scanned']} files, {$report['duration_ms']} ms){$reset}\n");
        return;
    }

    $counts = [];
    foreach ($findings as $f) {
        $counts[$f['severity']] = ($counts[$f['severity']] ?? 0) + 1;
    }

    fwrite(STDOUT, "{$bold}keybleed {$report['version']}{$reset}  {$report['files_scanned']} files, " . count($findings) . " findings\n\n");
    foreach ($findings as $f) {
        $paint = match ($f['severity']) {
            'critical' => $color ? "\033[1;31m" : '',
            'high' => $color ? "\033[31m" : '',
            'medium' => $color ? "\033[33m" : '',
            default => $color ? "\033[36m" : '',
        };
        $sev = strtoupper($f['severity']);
        fwrite(STDOUT, "{$paint}{$sev}{$reset}  {$f['rule']}\n");
        fwrite(STDOUT, "  {$dim}{$f['file']}:{$f['line']}{$reset}  {$f['redacted']}\n");
    }
    fwrite(STDOUT, "\n");
    $parts = [];
    foreach (['critical', 'high', 'medium', 'low'] as $level) {
        if (!empty($counts[$level])) {
            $parts[] = $counts[$level] . ' ' . $level;
        }
    }
    $blocking = count(kb_above($findings, $failOn));
    fwrite(STDOUT, implode(', ', $parts) . "  {$dim}(fail-on={$failOn}, blocking {$blocking}){$reset}\n");
}

function kb_self_test(): int
{
    $dir = sys_get_temp_dir() . '/keybleed-selftest-' . bin2hex(random_bytes(4));
    if (!mkdir($dir) && !is_dir($dir)) {
        fwrite(STDERR, "keybleed: cannot create temp dir\n");
        return 1;
    }

    try {
        kb_assert_rules();
        kb_assert_placeholders();
        $expect = kb_write_fixtures($dir);
        $report = kb_run_scan($dir, false);
        $rules = array_column($report['findings'], 'rule');
        foreach ($expect as $rule) {
            if (!in_array($rule, $rules, true)) {
                throw new RuntimeException("fixture missed rule {$rule}; got " . implode(',', $rules));
            }
        }
        $slack = array_filter($report['findings'], static fn (array $f): bool => $f['rule'] === 'slack_token');
        $npm = array_filter($report['findings'], static fn (array $f): bool => $f['rule'] === 'npm_token');
        $sendgrid = array_filter($report['findings'], static fn (array $f): bool => $f['rule'] === 'sendgrid');
        if ($slack !== [] || $npm !== [] || $sendgrid !== []) {
            throw new RuntimeException('ignored paths or keybleed-ignore comments were reported');
        }
        $aws = array_values(array_filter($report['findings'], static fn (array $f): bool => $f['rule'] === 'aws_access_key'));
        if (count($aws) !== 1) {
            throw new RuntimeException('expected exactly one real AWS key, not the documented example');
        }
        foreach ($report['findings'] as $f) {
            if (str_contains($f['redacted'], 'BEGIN')) {
                throw new RuntimeException('private key was not redacted');
            }
        }

        $php = escapeshellarg(PHP_BINARY !== '' ? PHP_BINARY : 'php');
        $script = escapeshellarg(__FILE__);
        $target = escapeshellarg($dir);

        exec("{$php} {$script} {$target} --json --no-color", $jsonOut, $jsonCode);
        $payload = json_decode(implode("\n", $jsonOut), true);
        if ($jsonCode !== 1 || !is_array($payload) || ($payload['ok'] ?? true) !== false) {
            throw new RuntimeException('CLI json scan should exit 1 on a leaky tree');
        }
        if (!isset($payload['findings'][0]['redacted']) || isset($payload['findings'][0]['secret'])) {
            throw new RuntimeException('JSON report must redact secrets and omit raw values');
        }

        $clean = $dir . '/clean-tree';
        mkdir($clean);
        file_put_contents($clean . '/.env.example', "APP_KEY=\nDB_PASSWORD=password\nAPI_TOKEN=changeme\n");
        exec("{$php} {$script} " . escapeshellarg($clean) . ' --no-color', $cleanOut, $cleanCode);
        if ($cleanCode !== 0) {
            throw new RuntimeException('clean tree should exit 0, got ' . $cleanCode . ' ' . implode("\n", $cleanOut));
        }

        exec("{$php} {$script} --help", $helpOut, $helpCode);
        if ($helpCode !== 0 || !str_contains(implode("\n", $helpOut), '--self-test')) {
            throw new RuntimeException('--help failed');
        }
        exec("{$php} {$script} --not-a-real-flag 2>/dev/null", $badOut, $badCode);
        if ($badCode !== 2) {
            throw new RuntimeException('unknown flag should exit 2');
        }

        if (kb_git_available()) {
            kb_assert_staged($php, $script);
        }

        fwrite(STDOUT, 'keybleed self-test: OK (' . count($report['findings']) . " findings in fixture, {$report['files_scanned']} files)\n");
        return 0;
    } catch (Throwable $e) {
        fwrite(STDERR, 'keybleed self-test: FAIL ' . $e->getMessage() . "\n");
        return 1;
    } finally {
        kb_rrmdir($dir);
    }
}

function kb_assert_rules(): void
{
    $aws = 'AKIA' . '1A2B3C4D5E6F7G8H';
    $samples = [
        'aws_access_key' => "AWS_ACCESS_KEY_ID={$aws}",
        'github_pat' => 'TOKEN=ghp_' . str_repeat('a', 36),
        'github_fine' => 'TOKEN=github_pat_' . str_repeat('a', 22) . '_' . str_repeat('b', 59),
        'gitlab_pat' => 'TOKEN=glpat-' . str_repeat('c', 20),
        'stripe_live' => 'STRIPE=sk_live_' . str_repeat('d', 24),
        'stripe_test' => 'STRIPE=sk_test_' . str_repeat('e', 24),
        'slack_token' => 'SLACK=xoxb-' . '1234567890-abcdefghij',
        'openai' => 'OPENAI_API_KEY=sk-proj-' . str_repeat('f', 32),
        'anthropic' => 'ANTHROPIC_API_KEY=sk-ant-' . str_repeat('g', 32),
        'google_api' => 'G=AIza' . str_repeat('h', 35),
        'sendgrid' => 'SENDGRID_API_KEY=SG.' . str_repeat('i', 22) . '.' . str_repeat('j', 22),
        'npm_token' => 'NPM_TOKEN=npm_' . str_repeat('k', 36),
        'private_key' => '-----BEGIN ' . 'PRIVATE KEY-----',
        'laravel_app_key' => 'APP_KEY=base64:' . base64_encode(random_bytes(32)),
        'jwt' => 'eyJhbGciOiJIUzI1NiJ9.' . kb_b64(18) . '.' . kb_b64(18),
        'db_url' => 'DATABASE_URL=mysql://app:' . 's3cure-Value-99x' . '@db.internal:3306/app',
        'generic_secret' => 'MAIL_PASSWORD=correct-horse-battery',
        'aws_temp_key' => 'AWS_SESSION_TOKEN=' . 'ASIA' . '1A2B3C4D5E6F7G8H',
        'github_oauth' => 'TOKEN=gho_' . str_repeat('a', 36),
        'slack_webhook' => 'https://hooks.slack.com/services/T' . str_repeat('A', 8) . '/B' . str_repeat('B', 8) . '/' . str_repeat('C', 24),
        'huggingface' => 'HF_TOKEN=hf_' . str_repeat('a', 34),
        'digitalocean' => 'DO=dop_v1_' . str_repeat('ab', 32),
        'shopify' => 'SHOP=shpat_' . str_repeat('ab', 16),
    ];
    foreach ($samples as $rule => $line) {
        $found = array_column(kb_analyze_line($line), 'rule');
        if (!in_array($rule, $found, true)) {
            throw new RuntimeException("rule {$rule} did not match its sample");
        }
    }
    $dummy = kb_analyze_line('AWS_ACCESS_KEY_ID=' . ('AKIA' . 'IOSFODNN7EXAMPLE'));
    if ($dummy !== []) {
        throw new RuntimeException('documented AWS example key must be ignored');
    }
    $comment = kb_analyze_line('SENDGRID_API_KEY=SG.' . str_repeat('i', 22) . '.' . str_repeat('j', 22) . ' # keybleed-ignore');
    if ($comment !== []) {
        throw new RuntimeException('keybleed-ignore comment was not honored');
    }
}

function kb_assert_placeholders(): void
{
    foreach ([
        'DB_PASSWORD=password',
        'API_TOKEN=changeme',
        'APP_KEY=',
        'SECRET_PATH=/var/www/html',
        'API_TOKEN=xxxxxxxx',
        'export DB_PASSWORD=example-value',
        'MAIL_PASSWORD=${MAIL_PASSWORD}',
    ] as $line) {
        if (kb_analyze_line($line) !== []) {
            throw new RuntimeException("placeholder should be quiet: {$line}");
        }
    }
}

/** @return list<string> */
function kb_write_fixtures(string $dir): array
{
    $aws = 'AKIA' . strtoupper(bin2hex(random_bytes(8)));
    $appKey = 'base64:' . base64_encode(random_bytes(32));
    $gh = 'ghp_' . kb_alnum(36);
    $stripe = 'sk_live_' . kb_alnum(24);
    $openai = 'sk-proj-' . kb_alnum(32);
    $dbPass = 'p' . kb_alnum(18);
    $mail = 'm' . kb_alnum(16);

    $dummyAws = 'AKIA' . 'IOSFODNN7EXAMPLE';
    $leaky = implode("\n", [
        'APP_NAME=Acme',
        'APP_KEY=' . $appKey,
        'AWS_ACCESS_KEY_ID=' . $aws,
        'AWS_ACCESS_KEY_ID_EXAMPLE=' . $dummyAws,
        'GITHUB_TOKEN=' . $gh,
        'STRIPE_SECRET=' . $stripe,
        'OPENAI_API_KEY=' . $openai,
        'DATABASE_URL=mysql://app:' . $dbPass . '@db.internal:3306/app',
        'MAIL_PASSWORD=' . $mail,
        'DB_PASSWORD=password',
        'API_TOKEN=changeme',
    ]) . "\n";
    file_put_contents($dir . '/.env', $leaky);
    file_put_contents($dir . '/.env.example', "APP_KEY=\nDB_PASSWORD=password\nAWS_SECRET=your_secret_here\n");
    file_put_contents($dir . '/notes.md', "token eyJhbGciOiJIUzI1NiJ9." . kb_b64(16) . '.' . kb_b64(16) . "\n");
    file_put_contents(
        $dir . '/allowed.php',
        "<?php\n\$k = 'SG." . str_repeat('a', 22) . '.' . str_repeat('b', 22) . "'; // keybleed-ignore\n"
    );

    mkdir($dir . '/vendor/pkg', 0777, true);
    file_put_contents($dir . '/vendor/pkg/leak.env', 'SLACK_TOKEN=xoxb-' . kb_alnum(24) . "\n");

    mkdir($dir . '/ignored', 0777, true);
    file_put_contents($dir . '/ignored/token.env', 'NPM_TOKEN=npm_' . kb_alnum(36) . "\n");
    file_put_contents($dir . '/.keybleedignore', "# local overrides\nignored/\n*.min.js\n");

    $begin = '-----BEGIN ' . 'PRIVATE KEY-----';
    $end = '-----END ' . 'PRIVATE KEY-----';
    file_put_contents($dir . '/key.pem', $begin . "\n" . base64_encode(random_bytes(32)) . "\n" . $end . "\n");

    return ['laravel_app_key', 'aws_access_key', 'github_pat', 'stripe_live', 'openai', 'db_url', 'generic_secret', 'jwt', 'private_key'];
}

function kb_assert_staged(string $php, string $script): void
{
    $repo = sys_get_temp_dir() . '/keybleed-git-' . bin2hex(random_bytes(3));
    mkdir($repo);
    try {
        exec('git init -q ' . escapeshellarg($repo), $o, $code);
        if ($code !== 0) {
            throw new RuntimeException('git init failed');
        }
        file_put_contents($repo . '/ok.txt', "APP_NAME=Acme\n");
        file_put_contents($repo . '/leak.env', 'API_TOKEN=' . kb_alnum(24) . "\n");
        exec('git -C ' . escapeshellarg($repo) . ' add ok.txt leak.env', $o, $code);
        if ($code !== 0) {
            throw new RuntimeException('git add failed');
        }
        exec("{$php} {$script} --staged --no-color " . escapeshellarg($repo), $out, $scanCode);
        if ($scanCode !== 1) {
            throw new RuntimeException('--staged should exit 1 when the index has a token');
        }
        $text = implode("\n", $out);
        if (!str_contains($text, 'leak.env') || str_contains($text, 'ok.txt')) {
            throw new RuntimeException('--staged scanned the wrong files');
        }
    } finally {
        kb_rrmdir($repo);
    }
}

function kb_git_available(): bool
{
    exec('git --version 2>/dev/null', $out, $code);
    return $code === 0;
}

function kb_b64(int $bytes): string
{
    return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
}

function kb_alnum(int $len): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $out = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
}

function kb_rrmdir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $file) {
        if ($file->isDir()) {
            rmdir($file->getPathname());
        } else {
            unlink($file->getPathname());
        }
    }
    rmdir($dir);
}

exit(kb_main($argv));
