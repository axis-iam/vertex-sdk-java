#!/usr/bin/env python3
"""Build local Maven candidates, then test a standalone app using JAR/POM only. Never publish remotely."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tarfile
import time
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build' / 'bff-consumer'
STAGE = WORK / 'candidate-repository'
CONSUMER = WORK / 'application'
PROXY = 'http://127.0.0.1:7897'

def run(args, cwd=ROOT):
    subprocess.run([str(x) for x in args], cwd=cwd, check=True)

def main():
    # Keep registry requests on the required proxy even when the parent has broad NO_PROXY entries.
    for key in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy'):
        os.environ[key]=PROXY
    os.environ['NO_PROXY']='localhost,127.0.0.1,::1'
    os.environ['no_proxy']='localhost,127.0.0.1,::1'
    WORK.mkdir(parents=True, exist_ok=True)
    # Chrome uses a Unix-domain singleton socket whose full path must remain below 108 bytes.
    task_tmp=ROOT/'.bft'
    task_tmp.mkdir(exist_ok=True)
    os.environ['TMPDIR']=str(task_tmp)
    STAGE.mkdir(exist_ok=True)
    run(['./gradlew', ':vertex-sdk-core:publishAllPublicationsToPublicationStagingRepository',
         ':vertex-sdk-web:publishAllPublicationsToPublicationStagingRepository',
         f'-PpublicationStagingRepository={STAGE}', '--max-workers=2'])
    artifacts = {}
    contents = {}
    bytecode = {}
    for module in ('vertex-sdk-core','vertex-sdk-web'):
        directory = STAGE / 'com/chaosguide/iam' / module / '0.1.0'
        for path in sorted(directory.iterdir()):
            if path.suffix in ('.jar','.pom'):
                artifacts[str(path.relative_to(STAGE))] = hashlib.sha256(path.read_bytes()).hexdigest()
                if path.suffix == '.jar':
                    with zipfile.ZipFile(path) as jar:
                        names=jar.namelist(); contents[str(path.relative_to(STAGE))]=names
                        assert not any(name.endswith(('TestIam.class','WebSessionContractTest.class','WebSessionMemoryTest.class')) for name in names)
                        majors=set()
                        for entry in jar.infolist():
                            name=entry.filename
                            assert not any(p in name for p in ('.env','docs/tasks/','/home/chaos/','.git/')), name
                            content=jar.read(entry)
                            assert b'/home/chaos/' not in content, name
                            assert not any(marker in content for marker in (b'fixture-secret',b'fixture-refresh-',b'fixture-control')), name
                            if name.endswith('.class'):
                                major=struct.unpack('>H',content[6:8])[0]; majors.add(major)
                                assert major <= 61, name
                        if majors: bytecode[str(path.relative_to(STAGE))]=sorted(majors)
                else:
                    ns={'m':'http://maven.apache.org/POM/4.0.0'}
                    pom=ET.parse(path)
                    assert pom.findtext('m:artifactId',namespaces=ns)==module
                    assert pom.find('m:licenses',ns) is not None
                    assert pom.find('m:scm',ns) is not None
    if CONSUMER.exists(): shutil.rmtree(CONSUMER)
    shutil.copytree(ROOT/'examples/bff-spring',CONSUMER)
    fixture=CONSUMER/'src/test/java/com/chaosguide/iam/vertex/web'
    fixture.mkdir(parents=True,exist_ok=True)
    (fixture/'TestIam.java').write_text((ROOT/'vertex-sdk-web/src/test/java/com/chaosguide/iam/vertex/web/TestIam.java').read_text().replace('WebWire', 'FixtureJson'))
    # Test fixture uses public protocol APIs; its local JSON helper is an independent fixture utility.
    (fixture/'FixtureJson.java').write_text('''package com.chaosguide.iam.vertex.web;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import com.fasterxml.jackson.databind.node.ObjectNode;
final class FixtureJson {
 static final ObjectMapper JSON=new ObjectMapper();
 static ObjectNode object(){return JSON.createObjectNode();}
 static ObjectNode parse(byte[] b){try{return (ObjectNode)JSON.readTree(b);}catch(IOException e){throw new AssertionError(e);}}
}
''')
    resources=CONSUMER/'src/test/resources/connected-app-bff'
    shutil.copytree(ROOT/'vertex-sdk-web/src/test/resources/connected-app-bff',resources,dirs_exist_ok=True)
    assert not list((CONSUMER/'src/main').rglob('com/chaosguide/iam/vertex/web/*.java'))
    browser_directory=CONSUMER/'browser'
    js_packages=json.loads((browser_directory/'vendor/SHA256SUMS.json').read_text())
    for archive_name,digest in js_packages.items():
        assert hashlib.sha256((browser_directory/'vendor'/archive_name).read_bytes()).hexdigest()==digest
    os.environ['PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD']='1'
    run(['npm','ci','--ignore-scripts','--no-audit','--no-fund','--registry=https://registry.npmjs.org',
         f'--proxy={PROXY}',f'--https-proxy={PROXY}'],browser_directory)
    for archive_name in js_packages:
        package_name='@axis-iam/vertex-react' if 'vertex-react' in archive_name else '@axis-iam/vertex'
        with tarfile.open(browser_directory/'vendor'/archive_name) as archive:
            for entry in archive.getmembers():
                if entry.isfile():
                    assert (browser_directory/'node_modules'/package_name/Path(entry.name).relative_to('package')).read_bytes()==archive.extractfile(entry).read()
    run(['node','build.mjs'],browser_directory)
    maven=shutil.which('mvn')
    if not maven:
        home=WORK/'apache-maven-3.9.9'
        if not (home/'bin/mvn').exists():
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({'http':PROXY,'https':PROXY}))
            url='https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.tar.gz'
            with opener.open(url,timeout=60) as response: raw=response.read()
            with opener.open(url+'.sha512',timeout=60) as response: expected=response.read().decode().strip().split()[0]
            assert hashlib.sha512(raw).hexdigest()==expected
            archive=WORK/'maven.tar.gz'; archive.write_bytes(raw)
            with tarfile.open(archive) as tar: tar.extractall(WORK,filter='data')
        maven=str(home/'bin/mvn')
    settings=WORK/'settings.xml'
    settings.write_text('<settings><proxies><proxy><id>task-proxy</id><active>true</active><protocol>http</protocol><host>127.0.0.1</host><port>7897</port><nonProxyHosts>localhost|127.*</nonProxyHosts></proxy></proxies></settings>')
    # Never let a previous candidate with the same unpublished version satisfy Maven resolution.
    cached_candidates=WORK/'m2/com/chaosguide/iam'
    if cached_candidates.exists(): shutil.rmtree(cached_candidates)
    run([maven,'-B','-q','-s',settings,f'-Dmaven.repo.local={WORK / "m2"}',
         f'-DcandidateRepository={STAGE.as_uri()}','-Dtest=example.BffConsumerTest','test'],CONSUMER)
    classpath_file=WORK/'consumer-classpath.txt'
    run([maven,'-B','-q','-s',settings,f'-Dmaven.repo.local={WORK / "m2"}',
         f'-DcandidateRepository={STAGE.as_uri()}',f'-Dmdep.outputFile={classpath_file}',
         'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath'],CONSUMER)
    ready=WORK/'browser-runtime.json'
    if ready.exists(): ready.unlink()
    classpath=os.pathsep.join([str(CONSUMER/'target/test-classes'),str(CONSUMER/'target/classes'),classpath_file.read_text().strip()])
    with (WORK/'browser-fixture.log').open('w') as fixture_log:
        fixture_process=subprocess.Popen(['java','-cp',classpath,'example.BffBrowserFixture',str(ready)],cwd=CONSUMER,stdout=fixture_log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+45
            while not ready.exists():
                if fixture_process.poll() is not None: raise RuntimeError('Browser fixture terminated; inspect browser-fixture.log')
                if time.monotonic()>deadline: raise TimeoutError('Browser fixture readiness exceeded 45 seconds')
                time.sleep(.1)
            run(['node','verify.mjs',ready],browser_directory)
        finally:
            fixture_process.terminate()
            try: fixture_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                fixture_process.kill(); fixture_process.wait(timeout=5)
    browser_result=json.loads((browser_directory/'browser-results.json').read_text())
    for module in ('vertex-sdk-core','vertex-sdk-web'):
        relative=Path('com/chaosguide/iam')/module/'0.1.0'/f'{module}-0.1.0.jar'
        assert hashlib.sha256((WORK/'m2'/relative).read_bytes()).hexdigest()==artifacts[str(relative)]
    (WORK/'artifact-contents.json').write_text(json.dumps(contents,indent=2)+'\n')
    results=[]
    for report in (CONSUMER/'target/surefire-reports').glob('TEST-*.xml'):
        root=ET.parse(report).getroot()
        results.append({k:root.attrib.get(k) for k in ('name','tests','failures','errors','skipped')})
        assert root.attrib['failures']=='0' and root.attrib['errors']=='0'
    assert results
    source_files={}
    tracked=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).split(b'\0')
    for raw_path in sorted(set(tracked)):
        if not raw_path: continue
        relative=raw_path.decode(); path=ROOT/relative
        if path.is_file(): source_files[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
    manifest={'validatedAtUtc':datetime.now(timezone.utc).isoformat(),'sourceFiles':source_files,'sourceTreeSha256':hashlib.sha256(json.dumps(source_files,sort_keys=True).encode()).hexdigest(),
              'baseline':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'sourcePatchSha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD'],cwd=ROOT)).hexdigest(),
              'artifacts':artifacts,'bytecodeMajorVersions':bytecode,'consumer':results,'jsPackages':js_packages,'browser':browser_result,'browserBundleSha256':hashlib.sha256((CONSUMER/'src/main/resources/static/bff-app.js').read_bytes()).hexdigest(),
              'combinedBrowser':'CONTROLLED_IAM_PASS_REAL_IAM_INPUTS_PENDING'}
    (WORK/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__': main()
