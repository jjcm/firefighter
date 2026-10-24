#!/usr/bin/env python3
"""Hermetic installer fixtures: no root, network, system service, or real install.

Production scripts have no test flags. Copies are mapped to a temporary root;
mock commands reject writes outside that root. Real controlling PTYs exercise
/dev/tty separately from piped script input, including on macOS development hosts.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
PHRASE = 'I understand the risks and that this might delete my entire server.'
BASH = shutil.which('bash') or '/bin/bash'

MOCK = r'''#!/usr/bin/env python3
import hashlib,json,os,pathlib,shutil,stat,sys,tempfile
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
elif name=='uname':print('Linux' if args==['-s'] else os.environ.get('FF_FIXTURE_ARCH','x86_64'))
elif name=='stat':
 p=pathlib.Path(args[-1]);mode=stat.S_IMODE(p.stat().st_mode)
 uid=os.environ.get('FF_FIXTURE_DIRECTORY_UID' if p.is_dir() else 'FF_FIXTURE_MARKER_UID','0')
 print(uid+':'+format(mode,'o'))
elif name=='curl':
 assert '--proto' in args and args[args.index('--proto')+1]=='=https'
 url=args[-1];assert url.startswith('https://45.76.243.18/downloads/')
 dest=target(args[args.index('--output')+1]);shutil.copyfile(root/'artifacts'/url.rsplit('/',1)[1],dest)
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
 assert args==['daemon-reload'], 'Installer must not start services'
 sys.exit(int(os.environ.get('FF_FIXTURE_RELOAD_FAILURE','0')))
else:raise RuntimeError('Unimplemented fixture command '+name)
'''

class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='firefighter-installer-test-')
        self.root = Path(self.temp.name)
        self.stage = self.root/'stage'
        self.bin = self.root/'mock-bin'
        self.bin.mkdir()
        for name in ('etc/systemd/system','var/lib','usr/local/bin','tmp'):
            (self.stage/name).mkdir(parents=True)
        (self.stage/'etc/os-release').write_text('ID=ubuntu\n')
        self.repo = self.root/'repo'
        shutil.copytree(REPO/'deploy',self.repo/'deploy')
        shutil.copytree(REPO/'plugins/grokbot',self.repo/'plugins/grokbot')
        (self.repo/'bin').mkdir()
        for name in ('firefighter','firefighter-grokbot'):
            p=self.repo/'bin'/name;p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
        dispatcher=self.bin/'mock';dispatcher.write_text(MOCK);dispatcher.chmod(0o755)
        for command in ('id','uname','stat','curl','sha256sum','mktemp','install','chmod','chown','mv','rm','systemctl'):
            (self.bin/command).symlink_to(dispatcher)
        self.env=dict(os.environ,FF_FIXTURE_ROOT=str(self.root),PATH=str(self.bin)+os.pathsep+os.environ['PATH'])
        for name in ('bootstrap.sh','install.sh','install-ack.sh'):
            p=self.repo/'deploy'/name
            text=p.read_text().replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin)+':'+os.environ['PATH'])
            for before,after in (('/etc/',str(self.stage/'etc')+'/'),('/var/lib/',str(self.stage/'var/lib')+'/'),('/usr/local/bin',str(self.stage/'usr/local/bin')),('/tmp/firefighter-install.',str(self.stage/'tmp/firefighter-install.'))):
                text=text.replace(before,after)
            p.write_text(text)
        self.artifacts=self.root/'artifacts';self.artifacts.mkdir()
        for arch in ('amd64','arm64'):(self.artifacts/('firefighter-linux-'+arch)).write_bytes(('fixture-'+arch).encode())
        for source,dest in [('firefighter-config.json','firefighter-config.json'),('firefighter-bootstrap.env.example','firefighter.env.example'),('firefighter.service','firefighter.service')]:
            shutil.copyfile(REPO/'deploy'/source,self.artifacts/dest)
        self.manifest()
    def close(self):self.temp.cleanup()
    def manifest(self):
        files=sorted(p for p in self.artifacts.iterdir() if p.name!='SHA256SUMS')
        (self.artifacts/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
    def acknowledgment(self,mode=0o600):
        p=self.stage/'etc/firefighter';p.mkdir(mode=0o700,exist_ok=True)
        marker=p/'install-risk-acknowledgment';marker.write_text(PHRASE+'\n');marker.chmod(mode)
        return marker
    def events(self):
        p=self.root/'events';return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    def run(self,kind='bootstrap',answer=None,script=None):
        file=self.repo/'deploy'/('bootstrap.sh' if kind=='bootstrap' else 'install.sh')
        code=script if script is not None else file.read_text()
        args=[BASH] if kind=='bootstrap' else [BASH,str(file)]
        data=code.encode() if kind=='bootstrap' else b''
        if answer is None:
            r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=self.env,start_new_session=True,timeout=15)
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
        output=bytearray();sent=False;deadline=time.monotonic()+15;status=None
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],0.05)
                if ready:
                    try:chunk=os.read(master,65536)
                    except OSError as exc:
                        if exc.errno!=errno.EIO:raise
                        chunk=b''
                    output.extend(chunk)
                    if b'\n> ' in output and not sent:
                        os.write(master,(answer+'\n').encode());sent=True
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
    def test_piped_script_reads_exact_acknowledgment_from_tty(self):
        code,out=self.f.run(answer=PHRASE);self.assertEqual(code,0,out)
        marker=self.f.stage/'etc/firefighter/install-risk-acknowledgment'
        self.assertEqual(marker.read_text(),PHRASE+'\n');self.assertEqual(marker.stat().st_mode&0o777,0o600)
        self.assertEqual((self.f.stage/'usr/local/bin/firefighter').read_bytes(),b'fixture-amd64')
        self.assertEqual([e for e in self.f.events() if e[0]=='systemctl'],[['systemctl','daemon-reload']])
        self.assertEqual((self.f.stage/'etc/firefighter/firefighter.env').stat().st_mode&0o777,0o600)
    def test_repository_installer_exact_acknowledgment(self):
        code,out=self.f.run('repo',answer=PHRASE);self.assertEqual(code,0,out)
        self.assertTrue((self.f.stage/'usr/local/bin/firefighter-grokbot').exists())
        self.assertTrue((self.f.stage/'etc/firefighter/install-risk-acknowledgment').exists())
    def test_upgrade_without_tty_preserves_local_configuration(self):
        self.f.acknowledgment()
        folder=self.f.stage/'etc/firefighter'
        (folder/'config.json').write_text('{"custom":"preserved"}\n');(folder/'firefighter.env').write_text('CUSTOM_KEY=fixture-only\n')
        for kind in ('bootstrap','repo'):
            with self.subTest(kind=kind):
                code,out=self.f.run(kind);self.assertEqual(code,0,out)
                self.assertEqual((folder/'config.json').read_text(),'{"custom":"preserved"}\n')
                self.assertEqual((folder/'firefighter.env').read_text(),'CUSTOM_KEY=fixture-only\n')
    def test_checksum_failure_installs_nothing_and_does_not_record_ack(self):
        (self.f.artifacts/'firefighter.service').write_text('tampered after manifest\n')
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0);self.assertIn('Checksum verification failed',out)
        self.assertFalse((self.f.stage/'etc/firefighter').exists())
        self.assertFalse(any(e[0] in ('install','systemctl') for e in self.f.events()))
    def test_duplicate_manifest_entry_is_rejected(self):
        p=self.f.artifacts/'SHA256SUMS';p.write_text(p.read_text()+next(x for x in p.read_text().splitlines() if x.endswith('firefighter-linux-amd64'))+'\n')
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0);self.assertIn('invalid checksum',out)
        self.assertFalse((self.f.stage/'etc/firefighter').exists())
    def test_architecture_arm64(self):
        self.f.acknowledgment();self.f.env['FF_FIXTURE_ARCH']='aarch64'
        code,out=self.f.run();self.assertEqual(code,0,out)
        self.assertEqual((self.f.stage/'usr/local/bin/firefighter').read_bytes(),b'fixture-arm64')
    def test_unsupported_architecture_fails_before_ack_or_mutation(self):
        self.f.env['FF_FIXTURE_ARCH']='riscv64'
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('architectures',out);self.assert_untouched()
    def test_non_ubuntu_fails_before_ack_or_mutation(self):
        (self.f.stage/'etc/os-release').write_text('ID=debian\n')
        code,out=self.f.run();self.assertNotEqual(code,0);self.assertIn('Ubuntu only',out);self.assert_untouched()
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
    def test_acknowledgment_not_persisted_when_reload_fails(self):
        self.f.env['FF_FIXTURE_RELOAD_FAILURE']='1'
        code,out=self.f.run(answer=PHRASE);self.assertNotEqual(code,0)
        self.assertFalse((self.f.stage/'etc/firefighter/install-risk-acknowledgment').exists())
    def test_truncated_pipe_never_begins_installation(self):
        text=(self.f.repo/'deploy/bootstrap.sh').read_text()
        code,out=self.f.run(script=text[:text.index('  ff_require_ack')+len('  ff_require_ack')])
        self.assertNotEqual(code,0);self.assert_untouched()

if __name__=='__main__':unittest.main(verbosity=2)
