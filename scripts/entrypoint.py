"""Materialize platform secret environment values into private per-process files."""
import os,sys,tempfile
from pathlib import Path
root=Path(tempfile.mkdtemp(prefix="jep-secrets-"))
for source,target in {"JEP_KEYRING_JSON":"JEP_KEYRING_FILE","JEP_SIGNING_TOKEN":"JEP_SIGNING_TOKEN_FILE","JEP_VAULT_TOKEN":"JEP_VAULT_TOKEN_FILE"}.items():
    value=os.environ.pop(source,None)
    if value is not None:
        if os.environ.get(target):raise ValueError("Conflicting signing secret configuration")
        path=root/source
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:f.write(value)
        os.environ[target]=str(path)
os.execvp(sys.argv[1],sys.argv[1:])
