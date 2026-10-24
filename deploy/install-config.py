#!/usr/bin/env python3
"""Installer-only JSON, terminal, and environment handling. Never executes keys."""
import json
import io
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import termios

PROVIDERS = {
    '1': ('OpenRouter', 'api', 'https://openrouter.ai/api/v1', 'OPENROUTER_API_KEY', 'deepseek/deepseek-v4.1-flash-1017', True),
    '2': ('OpenAI', 'api', 'https://api.openai.com/v1', 'OPENAI_API_KEY', 'gpt-6.1-sol', False),
    '3': ('Anthropic', 'anthropic', 'https://api.anthropic.com/v1', 'ANTHROPIC_API_KEY', 'claude-sonnet-5-5', False),
}


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
        die('Cannot disable terminal echo. No API key was read; retry from an interactive terminal.')
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
        terminal.write('Credentials accepted for local configuration. Starting after compilation and local checks.\n')

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


def main():
    command, *args = sys.argv[1:]
    if command == 'configure':
        configure(args)
    elif command == 'doctor':
        binary, config, environment = args
        child_env = dict(os.environ)
        child_env.update(parse_env(Path(environment).read_text()))
        result = subprocess.run([binary, 'doctor', '--config', config], env=child_env)
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
