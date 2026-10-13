from pathlib import Path
import subprocess,tempfile
# Requires the OpenSSL CLI only when regenerating these disposable test keys.
output=Path(__file__).resolve().parent/'unicode-subject-chain.p12'
def run(*args):
    return subprocess.run(['openssl',*map(str,args)],check=True,capture_output=True).stdout
with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    for name in ['root','leaf']:
        run('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',root/f'{name}.key')
    run('req','-new','-x509','-utf8','-subj','/CN=Issuer🚀','-key',root/'root.key','-out',root/'root.pem','-days','36500','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    run('req','-new','-utf8','-subj','/CN=Leaf🔑','-key',root/'leaf.key','-out',root/'leaf.csr')
    run('x509','-req','-in',root/'leaf.csr','-CA',root/'root.pem','-CAkey',root/'root.key','-set_serial','2','-days','36500','-out',root/'leaf.pem')
    run('verify','-CAfile',root/'root.pem',root/'leaf.pem')
    run('pkcs12','-export','-inkey',root/'leaf.key','-in',root/'leaf.pem','-certfile',root/'root.pem','-name','identity','-iter','1000','-passout','pass:fixture-password','-out',output)
print('Generated disposable Unicode-subject chain fixture.')
