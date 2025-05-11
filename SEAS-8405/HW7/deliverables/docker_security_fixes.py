import json
from pathlib import Path
import yaml

# -- 1. Update daemon.json --

def update_daemon_json(path='/etc/docker/daemon.json'):
    daemon = {}
    daemon_path = Path(path)

    if daemon_path.exists():
        with open(daemon_path, 'r') as f:
            try:
                daemon = json.load(f)
            except json.JSONDecodeError:
                print("Warning: existing daemon.json is invalid JSON")

    daemon.update({
        "icc": False,
        "userns-remap": "default",
        "live-restore": True,
        "userland-proxy": False
    })

    with open(daemon_path, 'w') as f:
        json.dump(daemon, f, indent=4)
    print(f"[+] Updated {path}")

# -- 2. Update Dockerfile --

def patch_dockerfile(path='./after/Dockerfile'):
    content = Path(path).read_text().splitlines()

    if not any("USER appuser" in line for line in content):
        content.append("USER appuser")

    if not any("HEALTHCHECK" in line for line in content):
        content.append(
            'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\')
        content.append(
            '  CMD wget --quiet --tries=1 --spider http://127.0.0.1:15000/ || exit 1')

    Path(path).write_text('\n'.join(content))
    print(f"[+] Patched {path}")

# -- 3. Patch docker-compose.yml --

def patch_compose(path='./after/docker-compose.yml'):
    compose_path = Path(path)
    if not compose_path.exists():
        print(f"[-] {path} not found.")
        return

    with open(compose_path, 'r') as f:
        compose = yaml.safe_load(f)

    for service_name, service in compose.get('services', {}).items():
        modified = False

        if 'build' in service or 'image' in service:
            if service.get('read_only') is not True:
                service['read_only'] = True
                modified = True

            if service.get('mem_limit') is None:
                service['mem_limit'] = '256m'
                modified = True

            if service.get('pids_limit') is None:
                service['pids_limit'] = 100
                modified = True

            if 'security_opt' not in service:
                service['security_opt'] = ['no-new-privileges:true']
                modified = True
            elif 'no-new-privileges:true' not in service['security_opt']:
                service['security_opt'].append('no-new-privileges:true')
                modified = True

            if service_name == "web":
                default_tmpfs = [
                    '/run:uid=1000,gid=1000,mode=1777',
                    '/var/log/nginx:uid=1000,gid=1000,mode=1777',
                    '/var/lib/nginx:uid=1000,gid=1000,mode=1777'
                ]

                existing_tmpfs = service.get('tmpfs', [])
                if isinstance(existing_tmpfs, str):
                    existing_tmpfs = [existing_tmpfs]

                existing_tmpfs_set = set(map(str.strip, existing_tmpfs))
                new_tmpfs = existing_tmpfs[:]

                for entry in default_tmpfs:
                    if entry not in existing_tmpfs_set:
                        new_tmpfs.append(entry)
                        modified = True

                service['tmpfs'] = new_tmpfs

        if modified:
            print(f"[+] Patched service: {service_name}")

    with open(compose_path, 'w') as f:
        yaml.dump(compose, f, sort_keys=False)
    print(f"[+] Patched {path}")

# -- Run all fixes --

if __name__ == "__main__":
    update_daemon_json()
    patch_dockerfile()
    patch_compose()