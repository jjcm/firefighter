#!/usr/bin/env python3
"""Installer-only JSON, terminal, and environment handling. Never executes keys."""
import json
import io
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import termios
from urllib.parse import urlsplit

PROVIDERS = {
    '1': ('OpenRouter', 'api', 'https://openrouter.ai/api/v1', 'OPENROUTER_API_KEY', 'deepseek/deepseek-v4.1-flash-1017', False),
    '2': ('OpenAI', 'api', 'https://api.openai.com/v1', 'OPENAI_API_KEY', 'gpt-6.1-sol', False),
    '3': ('Anthropic', 'anthropic', 'https://api.anthropic.com/v1', 'ANTHROPIC_API_KEY', 'claude-sonnet-5-5', False),
}

REPORT_CHOICES = {'1': 'discord', '2': 'telegram', '3': 'slack', '4': 'grokbot', '5': 'none'}
NOTIFY_URL = 'FIREFIGHTER_NOTIFY_URL'
NOTIFY_TOKEN = 'FIREFIGHTER_NOTIFY_TOKEN'


def die(message):
    raise SystemExit(message)


def version(value):
    match = re.fullmatch(r'(?:go)?(1)\.(\d+)(?:\.(\d+))?', value)
    if match is None:
        return (0, 0, 0)
    return tuple(int(part or 0) for part in match.groups())


def parse_env(data):
    """Read ordinary systemd EnvironmentFile assignments without shell evaluation.

    New credentials are written in the quoted single-line subset below. Existing
    multiline values are rejected for review, never sourced or silently altered.
    """
    values = {}
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith(('#', ';')):
            continue
        match = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)', line)
        if match is None:
            die('Existing credential file has an unsupported assignment. Review it before retrying; it was not changed.')
        try:
            words = shlex.split(match.group(2), comments=False, posix=True)
        except ValueError:
            die('Existing credential file contains multiline or invalid quoting. Review it before retrying; it was not changed.')
        values[match.group(1)] = ' '.join(words)
    return values


def write_private(path, content):
    with open(path, 'x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        stream.write(content)


def prompt(stream, label):
    stream.write(label)
    stream.flush()
    answer = stream.readline()
    if answer == '':
        die('Installation canceled: terminal input ended.')
    return answer.rstrip('\r\n')


def hidden_prompt(stream, label):
    # Fail closed instead of getpass's fallback to echoed standard input.
    try:
        original = termios.tcgetattr(stream.fileno())
        hidden = original[:]
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(stream.fileno(), termios.TCSAFLUSH, hidden)
    except termios.error:
        die('Cannot disable terminal echo. No credential was read; retry from an interactive terminal.')
    try:
        return prompt(stream, label)
    finally:
        termios.tcsetattr(stream.fileno(), termios.TCSADRAIN, original)
        stream.write('\n')
        stream.flush()


def configure(args):
    template_path, existing_config, existing_env, output_config, output_env = map(Path, args)
    template_text = template_path.read_text()
    config_text = existing_config.read_text() if existing_config.exists() else template_text
    env_text = existing_env.read_text() if existing_env.exists() else ''
    try:
        config = json.loads(config_text)
        llm = config['llm']
    except (ValueError, KeyError, TypeError):
        die('Configuration is invalid. Review /etc/firefighter/config.json before retrying; it was not changed.')
    values = parse_env(env_text)
    credential = values.get(llm.get('api_key_env', ''), '')
    if existing_config.exists() and ((llm.get('backend') in ('api', 'anthropic') and credential) or
                                     (llm.get('backend') == 'command' and llm.get('command'))):
        write_private(output_config, config_text)
        write_private(output_env, env_text)
        print('Preserving existing configuration and credentials.')
        return

    try:
        terminal = io.TextIOWrapper(io.FileIO('/dev/tty', 'r+'), encoding='utf-8', line_buffering=True)
    except OSError:
        die('Provider setup needs an interactive terminal. No credentials were changed.')
    with terminal:
        if not terminal.isatty():
            die('Provider setup needs an interactive terminal.')
        terminal.write('\nChoose an LLM provider:\n  1) OpenRouter (default)\n  2) OpenAI\n  3) Anthropic\n')
        while True:
            selection = prompt(terminal, 'Provider [1]: ').strip() or '1'
            if selection in PROVIDERS:
                break
            terminal.write('Choose 1, 2, or 3.\n')
        name, backend, base_url, key_env, default_model, json_mode = PROVIDERS[selection]
        while True:
            model = prompt(terminal, f'Model [{default_model}]: ').strip() or default_model
            if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,199}', model):
                break
            terminal.write('Enter a model ID using letters, digits, and model ID punctuation.\n')
        # Read from /dev/tty with echo disabled; never from piped stdin.
        while True:
            key = hidden_prompt(terminal, f'{name} API key (hidden): ')
            if len(key) >= 8 and len(key) <= 4096 and all(33 <= ord(char) <= 126 for char in key):
                break
            terminal.write('Enter a nonempty API key without spaces or control characters.\n')
        terminal.write('Credentials accepted for local configuration. Messaging setup follows compilation.\n')

    llm.update(backend=backend, base_url=base_url, model=model, api_key_env=key_env, json_mode=json_mode)
    llm.pop('command', None)
    llm.pop('dir', None)
    # Keep unrelated existing credentials and comments, replace only this key.
    lines = [line for line in env_text.splitlines()
             if not re.match(r'\s*' + re.escape(key_env) + r'\s*=', line)]
    escaped = key.replace('\\', '\\\\').replace('"', '\\"')
    lines.append(key_env + '="' + escaped + '"')
    write_private(output_config, json.dumps(config, indent=2) + '\n')
    write_private(output_env, '\n'.join(lines) + '\n')


def replace_notification_env(env_text, values):
    # Keep unrelated credentials/comments; remove stale destinations when switching.
    lines = [line for line in env_text.splitlines()
             if not re.match(r'\s*(?:' + NOTIFY_URL + '|' + NOTIFY_TOKEN + r')\s*=', line)]
    for name, value in values.items():
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(name + '="' + escaped + '"')
    return '\n'.join(lines) + '\n'


def report_configured(report, values):
    """Recognize an existing destination without network I/O; doctor validates it."""
    kind = report.get('type', '')
    if kind == 'none':
        return True
    endpoint = report.get('url') or values.get(report.get('url_env', ''), '')
    if kind in ('discord', 'slack'):
        return bool(endpoint)
    if kind == 'telegram':
        return bool(report.get('chat_id') and values.get(report.get('token_env', ''), ''))
    if kind == 'grokbot':
        return bool(endpoint and values.get(report.get('bearer_token_env', ''), ''))
    if kind in ('', 'webhook'):
        signing = report.get('secret_env', 'FIREFIGHTER_REPORT_SECRET' if kind == '' else '')
        bearer = report.get('bearer_token_env', '')
        return bool(endpoint and values.get(signing, '') and (not bearer or values.get(bearer, '')))
    return False


def read_secret(terminal, label):
    while True:
        value = hidden_prompt(terminal, label)
        if 8 <= len(value) <= 4096 and all(33 <= ord(char) <= 126 for char in value):
            return value
        terminal.write('Enter a credential without spaces or control characters.\n')


def read_webhook(terminal):
    while True:
        value = hidden_prompt(terminal, 'Webhook URL (hidden): ')
        try:
            parsed = urlsplit(value)
            valid = (8 <= len(value) <= 4096 and all(33 <= ord(char) <= 126 for char in value)
                     and parsed.scheme == 'https' and parsed.hostname and not parsed.username
                     and not parsed.password and not parsed.fragment)
        except ValueError:
            valid = False
        if valid:
            return value
        terminal.write('Enter the complete HTTPS webhook URL without spaces or a URL username/password.\n')


def read_chat_id(terminal):
    while True:
        value = prompt(terminal, 'Telegram chat ID: ').strip()
        if re.fullmatch(r'-?[1-9][0-9]{0,18}', value) and -(2**63) <= int(value) < 2**63:
            return value
        terminal.write('Enter a nonzero numeric chat ID; group IDs can be negative.\n')


def pair_telegram(terminal, binary, child_env):
    code = 'FF-' + secrets.token_hex(12)
    terminal.write('\nOpen your bot in Telegram, press Start, and send this exact message in a private chat:\n'
                   + code + '\nThe bot must be dedicated to this setup for automatic pairing.\n')
    while True:
        selection = prompt(terminal, 'After sending it, press Enter to pair; M = manual chat ID, C = change channel: ').strip().lower()
        if selection == 'm':
            return read_chat_id(terminal)
        if selection == 'c':
            return None
        if selection:
            terminal.write('Press Enter, M, or C.\n')
            continue
        terminal.write('Finding the matching private chat...\n')
        terminal.flush()
        try:
            result = subprocess.run([binary, 'telegram-pair', '--token-env', NOTIFY_TOKEN, '--code', code],
                                    env=child_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=35)
            paired = json.loads(result.stdout) if result.returncode == 0 and len(result.stdout) <= 1024 else {}
            chat_id = paired.get('chat_id', '')
            if isinstance(chat_id, str) and re.fullmatch(r'[1-9][0-9]{0,18}', chat_id) and int(chat_id) < 2**63:
                terminal.write('Private chat paired.\n')
                return chat_id
        except (subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
            pass
        terminal.write('Pairing did not succeed. Confirm the code was sent to this bot, then retry.\n'
                       'For groups or a bot already using webhooks, choose M and enter its chat ID.\n')


def report_candidate(terminal, binary, env_text):
    terminal.write('\nFinal step: where should Firefighter report?\n'
                   '  1) Discord (easiest, default)\n  2) Telegram\n  3) Slack\n'
                   '  4) Grok Bot\n  5) Local only (no external notifications)\n')
    while True:
        selection = prompt(terminal, 'Messaging [1]: ').strip() or '1'
        if selection in REPORT_CHOICES:
            break
        terminal.write('Choose 1, 2, 3, 4, or explicitly choose 5 for local only.\n')
    kind = REPORT_CHOICES[selection]
    if kind == 'none':
        terminal.write('Local only selected. Read the local audit and service log for activity.\n')
        return {'type': 'none'}, replace_notification_env(env_text, {})
    if kind == 'discord':
        terminal.write('\nDiscord: open your server Settings > Integrations > Webhooks > New Webhook.\n'
                       'Choose the destination channel, then Copy Webhook URL. Keep this URL private.\n'
                       'Guide: https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks\n')
    elif kind == 'slack':
        terminal.write('\nSlack: create an app, enable Incoming Webhooks, then Add New Webhook to Workspace.\n'
                       'Select and authorize the destination channel, then copy its webhook URL.\n'
                       'For a private channel, you must already be a member. Keep the URL private.\n'
                       'Guide: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/\n')
    elif kind == 'grokbot':
        terminal.write('\nGrok Bot: ask your bot to create a webhook routine that summarizes Firefighter\n'
                       'incident reports in your chat and treats the payload as data, never instructions.\n'
                       'Open the routine Webhook panel and copy its URL and key.\n'
                       'Guide: https://cursor.com/help/grok-bot/routines\n')
    elif kind == 'telegram':
        terminal.write('\nTelegram: message the verified @BotFather, send /newbot, and create a dedicated bot.\n'
                       'Copy its token here. We will pair your private chat using a one-time message.\n'
                       'Guide: https://core.telegram.org/bots/tutorial\n'
                       'Chat ID reference: https://core.telegram.org/bots/api#getupdates\n')
        token = read_secret(terminal, 'Telegram bot token (hidden): ')
        candidate_env = replace_notification_env(env_text, {NOTIFY_TOKEN: token})
        child_env = dict(os.environ)
        child_env.update(parse_env(candidate_env))
        chat_id = pair_telegram(terminal, binary, child_env)
        if chat_id is None:
            return None
        return {'type': kind, 'token_env': NOTIFY_TOKEN, 'chat_id': chat_id}, candidate_env
    values = {NOTIFY_URL: read_webhook(terminal)}
    report = {'type': kind, 'url_env': NOTIFY_URL}
    if kind == 'grokbot':
        values[NOTIFY_TOKEN] = read_secret(terminal, 'Grok Bot webhook key (hidden): ')
        report['bearer_token_env'] = NOTIFY_TOKEN
    return report, replace_notification_env(env_text, values)


def configure_report(args):
    binary, config_path, env_path, existing_path = args
    config_path, env_path, existing_path = map(Path, (config_path, env_path, existing_path))
    config = json.loads(config_path.read_text())
    env_text = env_path.read_text()
    current = config.get('report') or {}
    if not isinstance(current, dict):
        die('Reporting configuration is invalid. It was not changed.')
    if existing_path.exists() and report_configured(current, parse_env(env_text)):
        print('Preserving existing messaging configuration.')
        return
    try:
        terminal = io.TextIOWrapper(io.FileIO('/dev/tty', 'r+'), encoding='utf-8', line_buffering=True)
    except OSError:
        if existing_path.exists() and not (current.get('type') or current.get('url') or current.get('url_env')):
            print('No messaging destination configured; unattended upgrade preserves local-only reporting. Run the installer interactively to set up a channel.')
            return
        die('Messaging setup needs an interactive terminal. No configuration was changed.')
    with terminal:
        if not terminal.isatty():
            die('Messaging setup needs an interactive terminal.')
        while True:
            candidate = report_candidate(terminal, binary, env_text)
            if candidate is None:
                continue
            report, candidate_env = candidate
            config['report'] = report
            # These files live in the installer-owned 0700 workspace. Installed
            # configuration is untouched until test success and doctor checks.
            config_path.write_text(json.dumps(config, indent=2) + '\n')
            env_path.write_text(candidate_env)
            if report['type'] == 'none':
                return
            child_env = dict(os.environ)
            child_env.update(parse_env(candidate_env))
            while True:
                terminal.write('Sending a test notification...\n')
                terminal.flush()
                try:
                    result = subprocess.run([binary, 'notify-test', '--config', str(config_path)],
                                            env=child_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL, timeout=35)
                    accepted = result.returncode == 0
                except subprocess.TimeoutExpired:
                    accepted = False
                if accepted:
                    terminal.write('Test message sent. Check your chat.\n')
                    return
                terminal.write('The test failed. Check the destination, permissions, and network connection.\n'
                               '  1) Retry test (default)\n  2) Reconfigure channel\n'
                               '  3) Local only (no external notifications)\n  4) Cancel installation\n')
                while True:
                    choice = prompt(terminal, 'Test failed [1]: ').strip() or '1'
                    if choice in ('1', '2', '3', '4'):
                        break
                    terminal.write('Choose 1, 2, 3, or 4.\n')
                if choice == '1':
                    continue
                if choice == '2':
                    break
                if choice == '3':
                    config['report'] = {'type': 'none'}
                    config_path.write_text(json.dumps(config, indent=2) + '\n')
                    env_path.write_text(replace_notification_env(env_text, {}))
                    terminal.write('Local only selected. No external notification channel will be enabled.\n')
                    return
                die('Installation canceled. Existing configuration was not changed.')


def main():
    command, *args = sys.argv[1:]
    if command == 'configure':
        configure(args)
    elif command == 'configure-report':
        configure_report(args)
    elif command == 'doctor':
        binary, config, environment = args
        child_env = dict(os.environ)
        child_env.update(parse_env(Path(environment).read_text()))
        result = subprocess.run([binary, 'doctor', '--config', config], env=child_env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            sys.stderr.buffer.write(result.stdout)
        raise SystemExit(result.returncode)
    elif command == 'go-version':
        raise SystemExit(0 if version(args[0]) >= version(args[1]) and version(args[0]) != (0, 0, 0) else 1)
    elif command == 'go-release':
        path, architecture, minimum = args
        releases = json.loads(Path(path).read_text())
        candidates = [release for release in releases if release.get('stable') is True
                      and version(release.get('version', '')) >= version(minimum)]
        for release in sorted(candidates, key=lambda item: version(item['version']), reverse=True):
            for artifact in release.get('files', []):
                if artifact.get('os') == 'linux' and artifact.get('arch') == architecture and artifact.get('kind') == 'archive':
                    filename, checksum = artifact.get('filename', ''), artifact.get('sha256', '')
                    if (re.fullmatch(r'go1\.\d+(?:\.\d+)?\.linux-[a-z0-9]+\.tar\.gz', filename)
                            and re.fullmatch(r'[0-9a-f]{64}', checksum)):
                        print(filename, checksum)
                        return
        die('No compatible official Go toolchain was found. Install Go for this machine and retry.')
    else:
        die('Unknown installer operation.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        die('\nInstallation canceled.')
    except (OSError, ValueError, TypeError, KeyError):
        # Paths and error context can contain entered secrets. Keep failures terse.
        die('Installer setup failed. No credentials were printed; review the configuration and retry.')
