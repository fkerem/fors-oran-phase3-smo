"""Exact-reference image recovery, availability audit and digest-preserving cache."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "image-availability-lock.json"
TRACE_DIRECTORY = None
TRACE_SEQUENCE = 0
ORIGINALS = {
    "docker.io/bitnami/mariadb-galera:10.5.8": "bitnamilegacy/mariadb-galera",
    "docker.io/bitnami/mariadb:10.5.8": "bitnamilegacy/mariadb",
    "docker.io/bitnami/elasticsearch:7.9.3": "bitnamilegacy/elasticsearch",
    "docker.io/bitnami/nginx:1.21.4": "bitnamilegacy/nginx",
    "docker.io/bitnami/mysqld-exporter:0.12.1-debian-10-r264": "prom/mysqld-exporter",
}
ACCEPT = ", ".join(("application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.index.v1+json"))

def load_lock(path=LOCK_PATH):
    lock = json.loads(Path(path).read_text())
    images = lock.get("images", [])
    if (lock.get("schema") != 1 or lock.get("platform") != "linux/amd64" or
            lock.get("cache_registry") != "10.10.1.1:5000" or
            lock.get("skopeo_package") != "1.4.1+ds1-1ubuntu0.1" or
            len(images) != 5 or {i.get("original") for i in images} != set(ORIGINALS)):
        raise ValueError("Unreviewed image lock layout or reference")
    for item in images:
        if item.get("source_repository") != "docker.io/" + ORIGINALS[item["original"]]:
            raise ValueError("Unreviewed source repository")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", "")):
            raise ValueError("Missing immutable manifest digest")
        if not item.get("provenance") or not item.get("application_version"):
            raise ValueError("Missing version/packaging provenance")
    return lock

def cache_repository(item, lock):
    return lock["cache_registry"] + "/phase3-compat/" + item["source_repository"].split("/", 1)[1]

def replacements(lock=None):
    lock = lock or load_lock()
    return {i["original"]: cache_repository(i, lock) + "@" + i["digest"] for i in lock["images"]}

def images_in(value):
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "image" and isinstance(item, str):
                result.add(item)
            else:
                result.update(images_in(item))
    elif isinstance(value, list):
        for item in value:
            result.update(images_in(item))
    return result

def run(argv, timeout=120):
    global TRACE_SEQUENCE
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Command timed out: " + argv[0]) from None
    if TRACE_DIRECTORY is not None and argv[0] in ('skopeo','dpkg-query'):
        TRACE_SEQUENCE+=1
        prefix=TRACE_DIRECTORY/('cache-command-%04d'%TRACE_SEQUENCE)
        prefix.with_suffix('.json').write_text(json.dumps({'argv':argv,'returncode':result.returncode},indent=2)+'\n')
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
    if result.returncode:
        # Registry/auth command stderr may contain credentials. Keep it out of public summaries.
        raise RuntimeError("Command failed (%d): %s" % (result.returncode, argv[0]))
    return result.stdout

def split_reference(image):
    if "://" in image or not image or re.search(r"\s", image):
        raise ValueError("Invalid image reference")
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = "docker.io", image
    if registry == "index.docker.io":
        registry = "docker.io"
    if "@" in repository:
        repository, reference = repository.rsplit("@", 1)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
            raise ValueError("Invalid image digest")
    elif ":" in repository.rsplit("/", 1)[-1]:
        repository, reference = repository.rsplit(":", 1)
    else:
        raise ValueError("Unreviewed unversioned image")
    if reference == "latest" or not repository or ".." in repository.split("/"):
        raise ValueError("Unreviewed mutable image")
    if registry == "docker.io" and "/" not in repository:
        repository = "library/" + repository
    return registry, repository, reference

def request_blob(registry, repository, resource, reference, manifest=True):
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    scheme = "http" if registry == "10.10.1.1:5000" else "https"
    headers = {"Accept": ACCEPT} if manifest else {}
    url = "%s://%s/v2/%s/%s/%s" % (scheme, host, repository, resource, reference)
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=40).read()
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        challenge = error.headers.get("WWW-Authenticate", "")
        if not challenge.startswith("Bearer "):
            raise ValueError("Registry requires unreviewed authentication") from None
        parts = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = parts.get("realm", "")
        auth = urllib.parse.urlparse(realm)
        allowed = {"registry-1.docker.io": "auth.docker.io", "quay.io": "quay.io",
                   "nexus3.o-ran-sc.org:10002": "nexus3.o-ran-sc.org"}
        if auth.scheme != "https" or auth.hostname != allowed.get(host):
            raise ValueError("Unreviewed registry token endpoint") from None
        query = urllib.parse.urlencode({"service": parts.get("service", ""), "scope": "repository:" + repository + ":pull"})
        with urllib.request.urlopen(realm + "?" + query, timeout=40) as response:
            token = json.load(response)
        headers["Authorization"] = "Bearer " + (token.get("token") or token["access_token"])
        return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=40).read()

def inspect(image):
    registry, repository, reference = split_reference(image)
    raw = request_blob(registry, repository, "manifests", reference)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if reference.startswith("sha256:") and reference != digest:
        raise ValueError("Registry manifest digest mismatch")
    manifest = json.loads(raw)
    if "manifests" in manifest:
        leaves = [m for m in manifest["manifests"] if m.get("platform", {}).get("os") == "linux" and
                  m.get("platform", {}).get("architecture") == "amd64"]
        if len(leaves) != 1:
            raise ValueError("Ambiguous or absent linux/amd64 manifest")
        result = inspect(registry + "/" + repository + "@" + leaves[0]["digest"])
        return dict(result, index_digest=digest)
    config_raw = request_blob(registry, repository, "blobs", manifest["config"]["digest"], False)
    if "sha256:" + hashlib.sha256(config_raw).hexdigest() != manifest["config"]["digest"]:
        raise ValueError("Registry config digest mismatch")
    config = json.loads(config_raw)
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError("Image config platform mismatch")
    return {"digest": digest, "platform": "linux/amd64", "config_digest": manifest["config"]["digest"],
            "entrypoint": config.get("config", {}).get("Entrypoint"),
            "command": config.get("config", {}).get("Cmd"), "user": config.get("config", {}).get("User")}

def audit(images, lock=None):
    lock = lock or load_lock()
    reviewed = {i["original"]: i for i in lock["images"]}
    reverse = {target: original for original, target in replacements(lock).items()}
    records = []
    for image in sorted(images):
        original = reverse.get(image, image)
        item = reviewed.get(original)
        source = item["source_repository"] + "@" + item["digest"] if item else image
        record = {"reference": image, "audited_source": source}
        try:
            record.update(inspect(source), available=True)
        except (OSError, ValueError, KeyError) as error:
            record.update(available=False, error_type=type(error).__name__)
        records.append(record)
    return {"lock_sha256": hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(), "images": records,
            "ready": bool(records) and all(r["available"] for r in records)}

def verify_registry_binding(containers):
    if len(containers) != 1 or not containers[0].get("State", {}).get("Running"):
        raise ValueError("Existing private registry is not running")
    bindings = containers[0].get("HostConfig", {}).get("PortBindings", {})
    if bindings != {"5000/tcp": [{"HostIp": "10.10.1.1", "HostPort": "5000"}]}:
        raise ValueError("Registry listener is not LAN-only")

def cache(lock=None):
    lock = lock or load_lock()
    verify_registry_binding(json.loads(run(["sudo", "docker", "inspect", "local-registry"])))
    version = run(["dpkg-query", "-W", "-f=${Version}", "skopeo"]).decode().strip()
    if version != lock["skopeo_package"]:
        raise ValueError("Install the reviewed Skopeo package without upgrading existing packages first")
    receipts = []
    for item in lock["images"]:
        source = item["source_repository"] + "@" + item["digest"]
        # Explicitly reject indexes for locked artifacts, including the ambiguous exporter index.
        verified = inspect(source)
        if "index_digest" in verified or verified["digest"] != item["digest"]:
            raise ValueError("Locked artifact is not the reviewed platform manifest")
        repository = cache_repository(item, lock)
        tag = "sha256-" + item["digest"].split(":", 1)[1]
        target = repository + ":" + tag
        try:
            existing = inspect(target)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            existing = None
        if existing and existing["digest"] != item["digest"]:
            raise ValueError("Refusing to overwrite an unexpected cache tag")
        if not existing:
            # The pinned Ubuntu Skopeo lacks the newer --preserve-digests flag.
            # Do not request conversion; reject any native-copy rewrite rather than adopt a new digest.
            with tempfile.TemporaryDirectory(prefix='phase3-copy-') as directory:
                digest_file=Path(directory)/'copied-digest'
                run(["skopeo", "copy", "--retry-times", "0", "--src-no-creds", "--dest-no-creds",
                     "--dest-tls-verify=false", "--digestfile",str(digest_file),
                     "docker://" + source, "docker://" + target], timeout=1800)
                if digest_file.read_text().strip()!=item['digest']:
                    raise ValueError('Native copy changed manifest digest; artifact rejected')
        tagged=inspect(target)
        if tagged!=verified:raise ValueError('Copied tag manifest/config differs from reviewed source')
        cached = inspect(repository + "@" + item["digest"])
        if cached != verified:
            raise ValueError("Cached manifest/config differs from reviewed source")
        receipts.append({"original": item["original"], "source": source,
                         "cache": repository + "@" + item["digest"], **verified})
    return receipts
