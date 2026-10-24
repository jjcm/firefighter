#!/usr/bin/env python3
"""Hermetic installer checks: no root, network, or real service mutation.

Copies of production entry points are mapped to a temporary filesystem. All
privileged commands reject paths outside it. Real PTYs exercise /dev/tty while
bootstrap stdin remains a pipe; no test switches exist in production scripts.
"""
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
PHRASE = 'I understand the risks and that this might delete my entire server.'
KEY = 'sk-fixture-private-$quoted\\"-key'
BASH = shutil.which('bash') or '/bin/bash'

MOCK = r'''#!/usr/bin/env python3
import hashlib,json,os,pathlib,shutil,stat,sys,tarfile,tempfile
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
root=pathlib.Path(os.environ['FF_FIXTURE_ROOT'])
stage=root/'stage'
def target(p):
 p=pathlib.Path(p)
 if not p.is_absolute() or not p.is_relative_to(stage):
  raise RuntimeError('Fixture rejected non-staged mutation: '+str(p))
 return p
if name not in ('id','uname','stat'):
 with (root/'events').open('a') as f:f.write(json.dumps([name,*args])+'\n')
if name=='id':print('0')
elif name=='uname':print(os.environ.get('FF_FIXTURE_OS','Linux') if args==['-s'] else os.environ.get('FF_FIXTURE_ARCH','x86_64'))
elif name=='stat':
 p=pathlib.Path(args[-1]);mode=stat.S_IMODE(p.stat().st_mode)
 uid=os.environ.get('FF_FIXTURE_DIRECTORY_UID' if p.is_dir() else 'FF_FIXTURE_MARKER_UID','0')
 print(uid+':'+format(mode,'o'))
elif name=='git':
 if 'init' in args:target(args[-1]).mkdir(parents=True)
 elif 'fetch' in args:
  assert args[-1]==os.environ['FF_FIXTURE_REV'];sys.exit(int(os.environ.get('FF_FIXTURE_FETCH_FAILURE','0')))
 elif 'checkout' in args:
  folder=target(args[args.index('-C')+1]);shutil.copytree(root/'repo',folder,dirs_exist_ok=True)
 elif 'rev-parse' in args:print(os.environ.get('FF_FIXTURE_CHECKOUT_REV',os.environ['FF_FIXTURE_REV']))
 elif 'remote' in args:assert args[-1]=='https://github.com/jjcm/firefighter.git'
 else:raise RuntimeError('Unexpected git command')
elif name=='go':
 if args==['env','GOVERSION']:print(os.environ.get('FF_FIXTURE_GO_VERSION','go1.27.2'))
 elif args[0]=='build':
  for key in ('GOOS','GOARCH','GOROOT','GOFLAGS','GOEXPERIMENT'):assert key not in os.environ
  for key,value in [('GOENV','off'),('GOTOOLCHAIN','local'),('GOWORK','off'),('CGO_ENABLED','0')]:assert os.environ[key]==value
  if os.environ.get('FF_FIXTURE_BUILD_FAILURE'):sys.exit(1)
  output=target(args[args.index('-o')+1]);output.write_text((root/'doctor-fixture').read_text());output.chmod(0o755)
 else:raise RuntimeError('Unexpected Go command')
elif name=='curl':
 assert '--proto' in args and args[args.index('--proto')+1]=='=https'
 url=args[-1];assert url.startswith('https://go.dev/dl/'), 'Only official toolchains may be downloaded; Firefighter must compile from source'
 dest=target(args[args.index('--output')+1]);shutil.copyfile(root/('go-releases.json' if url.endswith('?mode=json') else 'go.tar.gz'),dest)
elif name=='tar':
 archive=pathlib.Path(args[args.index('-xzf')+1]);dest=target(args[args.index('-C')+1])
 with tarfile.open(archive) as stream:
  assert all(item.name=='go/bin/go' and item.isfile() for item in stream.getmembers())
  stream.extractall(dest)
elif name=='sha256sum':
 p=pathlib.Path(args[0]);print(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p))
elif name=='mktemp':
 template=target(args[-1]);prefix=template.name.split('XXXXXX')[0]
 if '-d' in args:print(tempfile.mkdtemp(prefix=prefix,dir=template.parent))
 else:
  fd,p=tempfile.mkstemp(prefix=prefix,dir=template.parent);os.close(fd);print(p)
elif name=='install':
 dirs=False;mode=0o755;paths=[];i=0
 while i<len(args):
  if args[i]=='-d':dirs=True;i+=1
  elif args[i] in ('-m','-o','-g'):
   if args[i]=='-m':mode=int(args[i+1],8)
   i+=2
  else:paths.append(args[i]);i+=1
 if dirs:
  for p in paths:q=target(p);q.mkdir(parents=True,exist_ok=True);q.chmod(mode)
 else:
  q=target(paths[1]);shutil.copyfile(paths[0],q);q.chmod(mode)
elif name=='chmod':
 for p in args[1:]:target(p).chmod(int(args[0],8))
elif name=='chown':
 for p in args[1:]:target(p)
elif name=='mv':
 paths=[p for p in args if p not in ('-T','--')];os.replace(target(paths[0]),target(paths[1]))
elif name=='rm':
 for p in args:
  if p.startswith('-'):continue
  q=target(p)
  if q.is_dir() and not q.is_symlink():shutil.rmtree(q)
  elif q.exists() or q.is_symlink():q.unlink()
elif name=='systemctl':
 assert args in (['daemon-reload'],['enable','firefighter'],['restart','firefighter'],['is-active','--quiet','firefighter'])
 if args[0]==os.environ.get('FF_FIXTURE_SYSTEMCTL_FAILURE'):sys.exit(1)
else:raise RuntimeError('Unimplemented fixture command '+name)
'''

DOCTOR = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
assert sys.argv[1]=='doctor'
config=json.loads(pathlib.Path(sys.argv[sys.argv.index('--config')+1]).read_text())
llm=config['llm']
assert llm['backend'] in ('api','anthropic','command')
if llm['backend']!='command':assert os.environ.get(llm['api_key_env'])==os.environ.get('FF_FIXTURE_EXPECTED_KEY')
print('Local doctor fixture passed; no API calls.')
sys.exit(int(os.environ.get('FF_FIXTURE_DOCTOR_FAILURE','0')))
'''


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='firefighter-installer-test-')
        self.root = Path(self.temp.name)
        self.stage = self.root/'stage'
        self.bin = self.root/'mock-bin'
        self.bin.mkdir()
        for name in ('etc/systemd/system','run/systemd/system','var/lib','usr/local/bin','tmp'):
            (self.stage/name).mkdir(parents=True)
        self.repo = self.root/'repo'
        shutil.copytree(REPO/'deploy',self.repo/'deploy',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(REPO/'plugins/grokbot',self.repo/'plugins/grokbot')
        shutil.copyfile(REPO/'go.mod',self.repo/'go.mod')
        self.revision = re.search(r'^FF_SOURCE_REV=([0-9a-f]{40})$',(REPO/'deploy/bootstrap.sh').read_text(),re.M).group(1)
        dispatcher=self.bin/'mock';dispatcher.write_text(MOCK);dispatcher.chmod(0o755)
        for command in ('id','uname','stat','git','go','curl','tar','sha256sum','mktemp','install','chmod','chown','mv','rm','systemctl'):
            (self.bin/command).symlink_to(dispatcher)
        (self.root/'doctor-fixture').write_text(DOCTOR)
        self.env=dict(os.environ,FF_FIXTURE_ROOT=str(self.root),FF_FIXTURE_REV=self.revision,FF_FIXTURE_EXPECTED_KEY=KEY,PATH=str(self.bin)+os.pathsep+os.environ['PATH'])
        # Production has no path override. Only copied test scripts are mapped.
        for name in ('bootstrap.sh','install.sh','install-ack.sh','install-runtime.sh'):
            p=self.repo/'deploy'/name
            text=p.read_text().replace('PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)+':'+os.environ['PATH'])
            for before,after in (('/etc/',str(self.stage/'etc')+'/'),('/run/systemd/system',str(self.stage/'run/systemd/system')),('/var/lib/',str(self.stage/'var/lib')+'/'),('/usr/local/bin',str(self.stage/'usr/local/bin')),('/tmp/firefighter-install.',str(self.stage/'tmp/firefighter-install.'))):
                text=text.replace(before,after)
            p.write_text(text)
        with tarfile.open(self.root/'go.tar.gz','w:gz') as archive:
            content=MOCK.encode();info=tarfile.TarInfo('go/bin/go');info.size=len(content);info.mode=0o755
            archive.addfile(info,io.BytesIO(content))
        checksum=hashlib.sha256((self.root/'go.tar.gz').read_bytes()).hexdigest()
        release=[{'version':'go1.27.2','stable':True,'files':[{'os':'linux','arch':'amd64','kind':'archive','filename':'go1.27.2.linux-amd64.tar.gz','sha256':checksum}]}]
        (self.root/'go-releases.json').write_text(json.dumps(release))
    def close(self):self.temp.cleanup()
    def acknowledgment(self,mode=0o600):
        p=self.stage/'etc/firefighter';p.mkdir(mode=0o700,exist_ok=True)
        marker=p/'install-risk-acknowledgment';marker.write_text(PHRASE+'\n');marker.chmod(mode)
        return marker
    def configured(self):
        self.acknowledgment()
        folder=self.stage/'etc/firefighter'
        config=json.loads((REPO/'deploy/firefighter-config.json').read_text());config['instructions']='Operator custom instructions preserved'
        text=json.dumps(config,indent=4)+'\n';env='OPENROUTER_API_KEY="fixture-preserved-key"\n# Preserve this comment\n'
        (folder/'config.json').write_text(text);(folder/'firefighter.env').write_text(env)
        self.env['FF_FIXTURE_EXPECTED_KEY']='fixture-preserved-key'
        return text,env
    def events(self):
        p=self.root/'events';return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    def run(self,kind='bootstrap',answer=None,provider='',model='',key=KEY,script=None,terminal=False):
        file=self.repo/'deploy'/('bootstrap.sh' if kind=='bootstrap' else 'install.sh')
        code=script if script is not None else file.read_text()
        args=[BASH] if kind=='bootstrap' else [BASH,str(file)]
        data=code.encode() if kind=='bootstrap' else b''
        if answer is None and not terminal:
            r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=self.env,start_new_session=True,timeout=20)
            return r.returncode,r.stdout.decode(errors='replace')
        reader,writer=os.pipe()
        pid,master=pty.fork()
        if pid==0:
            os.close(writer);os.dup2(reader,0);os.close(reader);os.execve(BASH,args,self.env)
        os.close(reader)
        try:
            offset=0
            while offset<len(data):offset+=os.write(writer,data[offset:])
        finally:os.close(writer)
        prompts=[]
        if answer is not None:prompts.append((b'\n> ',answer))
        prompts.extend([(b'Provider [1]: ',provider),(b']: ',model),(b'API key (hidden): ',key)])
        output=bytearray();pending=bytearray();deadline=time.monotonic()+20;status=None
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],0.05)
                if ready:
                    try:chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno!=errno.EIO:raise
                        chunk=b''
                    output.extend(chunk);pending.extend(chunk)
                    if prompts and prompts[0][0] in pending:
                        marker,value=prompts.pop(0)
                        pending=bytearray(pending.split(marker,1)[1])
                        os.write(master,(value+'\n').encode())
                done,status_now=os.waitpid(pid,os.WNOHANG)
                if done:status=status_now;break
            if status is None:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
                raise AssertionError('Installer fixture timed out: '+output.decode(errors='replace'))
        finally:os.close(master)
        return os.waitstatus_to_exitcode(status),output.decode(errors='replace')


class InstallTests(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def tearDown(self):self.f.close()
    def assert_untouched(self):
        self.assertEqual([],self.f.events())
        self.assertFalse((self.f.stage/'usr/local/bin/firefighter').exists())
    def assert_not_started(self):
        self.assertFalse(any(e[0]=='systemctl' for e in self.f.events()))
        self.assertFalse((self.f.stage/'etc/firefighter/install-risk-acknowledgment').exists())
    def test_acknowledgment_blocks_are_identical(self):
        def block(p):
            t=p.read_text();a=t.index('# BEGIN FIREFIGHTER INSTALL ACK');b=t.index('# END FIREFIGHTER INSTALL ACK')
            return t[a:b]
        self.assertEqual(block(REPO/'deploy/install-ack.sh'),block(REPO/'deploy/bootstrap.sh'))
    def test_no_terminal_fails_before_mutation_for_both_installers(self):
        for kind in ('bootstrap','repo'):
            with self.subTest(kind=kind):
                code,out=self.f.run(kind);self.assertNotEqual(code,0);self.assertIn('interactive terminal',out);self.assert_untouched()
    def test_wrong_acknowledgment_fails_before_mutation(self):
        for kind in ('bootstrap','repo'):
            with self.subTest(kind=kind):
                code,out=self.f.run(kind,answer=PHRASE+' ');self.assertNotEqual(code,0);self.assertIn('did not match exactly',out);self.assert_untouched()
    def test_interactive_source_install_starts_service_and_hides_key(self):
        code,out=self.f.run(answer=PHRASE);self.assertEqual(code,0,out)
        folder=self.f.stage/'etc/firefighter';marker=folder/'install-risk-acknowledgment'
        self.assertEqual(marker.read_text(),PHRASE+'\n');self.assertEqual(marker.stat().st_mode&0o777,0o600)
        self.assertEqual([e for e in self.f.events() if e[0]=='systemctl'],[['systemctl','daemon-reload'],['systemctl','enable','firefighter'],['systemctl','restart','firefighter'],['systemctl','is-active','--quiet','firefighter']])
        self.assertEqual((folder/'firefighter.env').stat().st_mode&0o777,0o600)
        self.assertNotIn(KEY,out);self.assertNotIn(KEY,json.dumps(self.f.events()))
        config=json.loads((folder/'config.json').read_text())
        self.assertEqual(config['llm']['api_key_env'],'OPENROUTER_API_KEY')
        self.assertEqual(config['llm']['model'],'deepseek/deepseek-v4.1-flash-1017')
        self.assertTrue(any(e[0]=='git' and 'fetch' in e and e[-1]==self.f.revision for e in self.f.events()))
        self.assertEqual(len([e for e in self.f.events() if e[:2]==['go','build']]),2)
        self.assertFalse(any(e[0]=='curl' for e in self.f.events()))
    def test_openai_provider_and_model_override(self):
        code,out=self.f.run(answer=PHRASE,provider='2',model='gpt-custom-model');self.assertEqual(code,0,out)
        llm=json.loads((self.f.stage/'etc/firefighter/config.json').read_text())['llm']
        self.assertEqual((llm['backend'],llm['base_url'],llm['api_key_env'],llm['model'],llm['json_mode']),('api','https://api.openai.com/v1','OPENAI_API_KEY','gpt-custom-model',False))
        self.assertNotIn(KEY,out)
    def test_anthropic_provider_uses_native_backend(self):
        code,out=self.f.run(answer=PHRASE,provider='3');self.assertEqual(code,0,out)
        llm=json.loads((self.f.stage/'etc/firefighter/config.json').read_text())['llm']
        self.assertEqual((llm['backend'],llm['base_url'],llm['api_key_env'],llm['model'],llm['json_mode']),('anthropic','https://api.anthropic.com/v1','ANTHROPIC_API_KEY','claude-sonnet-5-5',False))
        self.assertNotIn(KEY,out)
    def test_repository_installer_builds_and_starts(self):
        code,out=self.f.run('repo',answer=PHRASE);self.assertEqual(code,0,out)
        self.assertTrue((self.f.stage/'usr/local/bin/firefighter-grokbot').exists())
        self.assertTrue((self.f.stage/'etc/firefighter/install-risk-acknowledgment').exists())
    def test_upgrade_without_tty_preserves_local_configuration(self):
        original_config,original_env=self.f.configured();folder=self.f.stage/'etc/firefighter'
        for kind in ('bootstrap','repo'):
            with self.subTest(kind=kind):
                code,out=self.f.run(kind);self.assertEqual(code,0,out)
                self.assertEqual((folder/'config.json').read_text(),original_config)
                self.assertEqual((folder/'firefighter.env').read_text(),original_env)
                self.assertNotIn('API key (hidden)',out)
    def test_existing_blank_configuration_gets_interactive_provider_setup(self):
        self.f.acknowledgment();folder=self.f.stage/'etc/firefighter'
        shutil.copyfile(REPO/'deploy/firefighter-config.json',folder/'config.json')
        (folder/'firefighter.env').write_text('OPENROUTER_API_KEY=\nKEEP_ME=value\n')
        code,out=self.f.run(terminal=True);self.assertEqual(code,0,out)
        self.assertIn('KEEP_ME=value',(folder/'firefighter.env').read_text())
    def test_build_failure_leaves_existing_installation_untouched(self):
        original_config,original_env=self.f.configured();self.f.env['FF_FIXTURE_BUILD_FAILURE']='1'
        binary=self.f.stage/'usr/local/bin/firefighter';binary.write_text('existing binary')
        code,out=self.f.run();self.assertNotEqual(code,0)
        self.assertEqual(binary.read_text(),'existing binary')
        self.assertEqual((self.f.stage/'etc/firefighter/config.json').read_text(),original_config)
        self.assertEqual((self.f.stage/'etc/firefighter/firefighter.env').read_text(),original_env)
        self.assertFalse(any(e[0]=='systemctl' for e in self.f.events()))
    def test_doctor_failure_never_installs_or_starts(self):
        self.f.env['FF_FIXTURE_DOCTOR_FAILURE']='1'
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0)
        self.assert_not_started();self.assertFalse((self.f.stage/'usr/local/bin/firefighter').exists())
    def test_fetch_failure_does_not_compile_or_start(self):
        self.f.env['FF_FIXTURE_FETCH_FAILURE']='1'
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0);self.assert_not_started()
        self.assertFalse(any(e[0]=='go' for e in self.f.events()))
    def test_wrong_source_revision_is_rejected(self):
        self.f.env['FF_FIXTURE_CHECKOUT_REV']='0'*40
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0);self.assertIn('pinned revision',out);self.assert_not_started()
    def test_non_ubuntu_and_alternative_architectures_use_local_compiler(self):
        self.f.env['FF_FIXTURE_ARCH']='riscv64';self.f.env['GOARCH']='amd64';self.f.env['GOOS']='darwin'
        code,out=self.f.run(answer=PHRASE);self.assertEqual(code,0,out)
        self.assertFalse(any(e[0]=='curl' for e in self.f.events()))
    def test_missing_systemd_fails_before_ack_or_mutation(self):
        (self.f.stage/'run/systemd/system').rmdir()
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('systemd',out);self.assert_untouched()
    def test_non_linux_fails_before_ack_or_mutation(self):
        self.f.env['FF_FIXTURE_OS']='Darwin'
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('Linux',out);self.assert_untouched()
    def test_old_go_downloads_checksum_verified_official_toolchain(self):
        self.f.env['FF_FIXTURE_GO_VERSION']='go1.18.1'
        code,out=self.f.run(answer=PHRASE);self.assertEqual(code,0,out)
        downloads=[e[-1] for e in self.f.events() if e[0]=='curl']
        self.assertEqual(downloads,['https://go.dev/dl/?mode=json','https://go.dev/dl/go1.27.2.linux-amd64.tar.gz'])
    def test_corrupt_toolchain_never_compiles_or_starts(self):
        self.f.env['FF_FIXTURE_GO_VERSION']='go1.18.1';(self.f.root/'go.tar.gz').write_text('corrupt archive')
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0);self.assertIn('checksum verification failed',out);self.assert_not_started()
        self.assertFalse(any(e[:2]==['go','build'] for e in self.f.events()))
    def test_insecure_marker_and_parent_are_rejected(self):
        marker=self.f.acknowledgment(mode=0o644)
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('0600',out);self.assert_untouched()
        marker.chmod(0o600);self.f.env['FF_FIXTURE_MARKER_UID']='1000'
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('owned by root',out);self.assert_untouched()
        del self.f.env['FF_FIXTURE_MARKER_UID'];marker.parent.chmod(0o777)
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('writable',out);self.assert_untouched()
        marker.parent.chmod(0o755);self.f.env['FF_FIXTURE_DIRECTORY_UID']='1000'
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('owned by root',out);self.assert_untouched()
    def test_symlink_marker_is_rejected(self):
        marker=self.f.acknowledgment();saved=marker.with_name('saved');marker.rename(saved);marker.symlink_to(saved)
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('symlink',out);self.assert_untouched()
    def test_acknowledgment_not_persisted_when_service_start_fails(self):
        self.f.env['FF_FIXTURE_SYSTEMCTL_FAILURE']='restart'
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0)
        self.assertFalse((self.f.stage/'etc/firefighter/install-risk-acknowledgment').exists())
    def test_truncated_pipe_never_begins_installation(self):
        text=(self.f.repo/'deploy/bootstrap.sh').read_text()
        code,out=self.f.run(script=text[:text.index('  ff_require_ack')+len('  ff_require_ack')])
        self.assertNotEqual(code,0);self.assert_untouched()

if __name__=='__main__':unittest.main(verbosity=2)
