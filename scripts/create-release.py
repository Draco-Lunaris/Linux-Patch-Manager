#!/usr/bin/env python3
"""Create a Gitea release and upload a .deb package as an asset.

Usage:
    python3 create-release.py --tag v1.0.0 --deb linux-patch-manager_1.0.0-1_amd64.deb

Environment variables:
    GITEA_TOKEN  - API token (required, falls back to GITHUB_TOKEN)
    GITEA_URL    - Gitea base URL (default: http://192.168.2.189:3000)
    GITEA_REPO   - Repository path (default: git-echo/linux_patch_manager)
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error


def create_release(base_url, repo, token, tag, title, body):
    url = f"{base_url}/api/v1/repos/{repo}/releases"
    data = json.dumps({
        "tag_name": tag,
        "title": title,
        "body": body,
    }).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        return result
    except urllib.error.HTTPError as e:
        print(f"ERROR: Failed to create release (HTTP {e.code}): {e.read().decode()[:500]}")
        sys.exit(1)


def upload_asset(base_url, repo, token, release_id, deb_path):
    url = f"{base_url}/api/v1/repos/{repo}/releases/{release_id}/assets"
    filename = os.path.basename(deb_path)
    boundary = "----FormBoundary7MA4YWxkTrZu0gW"
    with open(deb_path, "rb") as f:
        deb_data = f.read()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="attachment"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + deb_data + (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="name"\r\n\r\n'
        f"{filename}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"token {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        return result
    except urllib.error.HTTPError as e:
        print(f"ERROR: Failed to upload asset (HTTP {e.code}): {e.read().decode()[:500]}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Create Gitea release with .deb asset")
    parser.add_argument("--tag", required=True, help="Tag name (e.g. v1.0.0)")
    parser.add_argument("--deb", required=True, help="Path to .deb file")
    parser.add_argument("--version", required=True, help="Version string")
    args = parser.parse_args()

    token = os.environ.get("GITEA_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
    if not token:
        print("ERROR: GITEA_TOKEN or GITHUB_TOKEN not set")
        sys.exit(1)

    base_url = os.environ.get("GITEA_URL", "http://192.168.2.189:3000")
    repo = os.environ.get("GITEA_REPO", "git-echo/linux_patch_manager")

    title = f"Release {args.version}"
    body = (
        f"Automated build from tag {args.tag}.\n\n"
        f"## Installation\n\n"
        f"```bash\n"
        f"sudo apt install ./{os.path.basename(args.deb)}\n"
        f"```\n"
    )

    print(f"Creating release for tag: {args.tag} repo: {repo}")
    print(f"DEB: {args.deb}")

    release = create_release(base_url, repo, token, args.tag, title, body)
    release_id = release["id"]
    print(f"Release created! ID: {release_id}")

    asset = upload_asset(base_url, repo, token, release_id, args.deb)
    print(f"Upload SUCCESS! Asset ID: {asset.get('id')}")
    print(f"Download URL: {asset.get('browser_download_url', 'N/A')}")
    print("Release upload complete")


if __name__ == "__main__":
    main()
