import os
import sys
import hashlib
import git
import requests
import gnupg
from datetime import datetime
from rfc3161ng import RemoteTimestamper
import random

TSA_URL = "http://timestamp.digicert.com"

def hash_file(filename):
    with open(filename, "rb") as f:
        file_hash = hashlib.sha256()
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def sign_file(filename, gpg):
    with open(filename, "rb") as f:
        signed_data = gpg.sign_file(f, detach=True)
    if not signed_data:
        print(f"Error signing {filename}")
        sys.exit(1)
    sig_filename = f"{filename}.sig"
    with open(sig_filename, "wb") as sig_file:
        sig_file.write(signed_data.data)
    return sig_filename

def timestamp_file(filename):
    """Timestamps a file using a trusted RFC 3161 timestamp authority (TSA)."""

    if not os.path.isfile(filename):
        print(f"Error: File not found - {filename}")
        return None

    try:
        with open(filename, "rb") as f:
            file_data = f.read()

        print(f"Requesting RFC 3161 timestamp from {TSA_URL} for {filename} (including full certificate)...")

        # Request full TSA certificate inclusion
        timestamper = RemoteTimestamper(TSA_URL, hashname='sha256', include_tsa_certificate=True)

        nonce = random.getrandbits(64)

        # Perform the timestamp and receive the raw response
        tst_response = timestamper.timestamp(
            data=file_data,
            nonce=nonce,
            include_tsa_certificate=True)

        # Save the timestamp response to a `.tsr` file
        ts_filename = filename + ".tsr"
        with open(ts_filename, "wb") as f:
            f.write(tst_response)

        print(f"Timestamp receipt (including certificate) saved: {ts_filename}")
        return ts_filename

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
    
def tag_repo(git_repo, tag_name, message):
    git_repo.create_tag(tag_name, message=message)

def create_github_release(repo_full_name, tag_name, body, token):
    url = f"https://api.github.com/repos/{repo_full_name}/releases"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    data = {"tag_name": tag_name, "name": tag_name, "body": body}
    response = requests.post(url, json=data, headers=headers)
    response.raise_for_status()
    return response.json()

def upload_asset(release, asset_path, token):
    upload_url = release['upload_url'].replace("{?name,label}", "")
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/octet-stream"
    }
    asset_name = os.path.basename(asset_path)
    with open(asset_path, 'rb') as f:
        response = requests.post(f"{upload_url}?name={asset_name}", headers=headers, data=f)
        response.raise_for_status()

def main(binary_path, tag_name, github_token):
    # Initialize GPG
    gpg = gnupg.GPG()

    # Hash the binary
    print(f"Hashing {binary_path}...")
    binary_hash = hash_file(binary_path)
    print(f"Hash: {binary_hash}")

    # Sign the binary
    print(f"Signing {binary_path}...")
    signature_file = sign_file(binary_path, gpg)

    # Timestamp the binary
    # Call timestamp_file function
    ts_file = timestamp_file(binary_path)
    sig_ts_file = timestamp_file(signature_file)

    # ✅ Check if timestamping failed
    if ts_file is None or sig_ts_file is None:
        print("Error: Timestamping failed! Exiting...")
        sys.exit(1)  # Prevent any further errors


    # Initialize Git repo
    repo = git.Repo(os.getcwd())

    # Tag the repository
    tag_message = f"Release for {tag_name}"
    tag_repo(repo, tag_name, tag_message)
    print(f"Tagged repository with {tag_name}")

    # Push the tag
    origin = repo.remote('origin')
    origin.push(tag_name)

    # Prepare release body including hash and timestamp info
    timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    release_body = f"""## Release Notes

- Binary SHA256 Hash: `{binary_hash}`
- Signed on: {timestamp_str}
- Timestamps receipts included:
  - `{os.path.basename(ts_file)}`
  - `{os.path.basename(sig_ts_file)}`
- Verify the timestamps at https://pkitools.net/pages/timestamp/readtsr.html
"""
    print(release_body)


    # Create the GitHub release
    repo_url = repo.remotes.origin.url
    if repo_url.startswith('git@github.com:'):
        repo_full_name = repo_url[15:-4].replace(':', '/')
    elif repo_url.startswith('https://github.com/'):
        repo_full_name = repo_url[19:-4]
    else:
        print(f"Unsupported repository URL format: {repo_url}")
        sys.exit(1)

    release_info = create_github_release(repo_full_name, tag_name, release_body, github_token)

    # Upload assets
    print("Uploading binary, signature, and timestamp receipts to GitHub release...")
    upload_asset(release_info, binary_path, github_token)
    upload_asset(release_info, signature_file, github_token)
    upload_asset(release_info, ts_file, github_token)
    upload_asset(release_info, sig_ts_file, github_token)

    print("Release created successfully!")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python github_sign_release.py <binary_path> <tag_name> <github_token>")
        sys.exit(1)

    binary_path = sys.argv[1]
    tag_name = sys.argv[2]
    github_token = sys.argv[3]

    main(binary_path, tag_name, github_token)