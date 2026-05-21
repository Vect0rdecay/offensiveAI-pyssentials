import contextlib
import os
import tempfile

@contextlib.contextmanager
def assumed_role_session(role_arn: str):
    """Temporarily swap AWS creds to an assumed role, then restore.
    Useful for lateral movement testing without polluting the host env."""
    import boto3
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="redteam")["Credentials"]

    # Stash originals so we can restore them -- never leave creds in env after exit
    saved = {k: os.environ.get(k) for k in
             ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")}
    os.environ["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    os.environ["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    try:
        yield boto3.Session()  # caller uses this session inside the `with` block
    finally:
        # Restore -- runs even if the caller raises, so creds never linger
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

# Usage: creds only exist for the duration of the block
# with assumed_role_session("arn:aws:iam::1234:role/victim") as sess:
#     s3 = sess.client("s3")
#     buckets = s3.list_buckets()

# tempfile context managers auto-delete -- good for staging payloads
with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as payload:
    payload.write(b"\x7fELF...")  # write shellcode/loader
    payload.flush()
    # exec or upload here; file vanishes when the block exits
