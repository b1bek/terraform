import requests
import sys
import time
import hashlib
import os

BASE_URL = "https://app.terraform.io/api/v2"
HEADERS_TEMPLATE = {
    "Content-Type": "application/vnd.api+json"
}
OUTPUT_FILE = "tfc_enum_output.txt"
RESUME_FILE = "tfc_enum_resume.log"


class TeeLogger:
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.logfile = open(filepath, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.logfile.write(message)
        self.logfile.flush()

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()


def get_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def load_processed_hashes():
    if not os.path.exists(RESUME_FILE):
        return set()
    with open(RESUME_FILE, "r") as f:
        return set(line.strip() for line in f)


def save_processed_hash(token_hash):
    with open(RESUME_FILE, "a") as f:
        f.write(token_hash + "\n")


def api_get(url, headers):
    results = []
    while url:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            print(f"    [!] Request failed: {r.status_code} - {r.text[:100]}")
            return results
        data = r.json()
        results.extend(data.get("data", []))
        url = data.get("links", {}).get("next")
    return results


def enumerate_token(token):
    print("=" * 80)
    print(f"[+] Enumerating token: {token[:10]}...")
    print("=" * 80)

    headers = HEADERS_TEMPLATE.copy()
    headers["Authorization"] = f"Bearer {token}"

    # Enumerate organizations
    orgs = api_get(f"{BASE_URL}/organizations", headers)
    if not orgs:
        print("[-] No organizations found or invalid token.")
        return

    for org in orgs:
        org_name = org["attributes"]["name"]
        org_email = org["attributes"].get("email")
        print(f"\n[+] Organization: {org_name}")
        if org_email:
            print(f"    - Email: {org_email}")

        # Teams
        print("  [*] Teams:")
        teams = api_get(f"{BASE_URL}/organizations/{org_name}/teams", headers)
        for team in teams:
            print(f"      - {team['attributes']['name']}")

        # Policy Sets
        print("  [*] Policy Sets:")
        policies = api_get(f"{BASE_URL}/organizations/{org_name}/policy-sets", headers)
        for policy in policies:
            print(f"      - {policy['attributes']['name']}")

        # Agent Pools
        print("  [*] Agent Pools:")
        agents = api_get(f"{BASE_URL}/organizations/{org_name}/agent-pools", headers)
        for agent in agents:
            print(f"      - {agent['attributes']['name']}")

        # Workspaces
        print("  [*] Workspaces:")
        workspaces = api_get(f"{BASE_URL}/organizations/{org_name}/workspaces", headers)

        for ws in workspaces:
            ws_id = ws["id"]
            ws_name = ws["attributes"]["name"]
            tf_version = ws["attributes"].get("terraform-version")
            auto_apply = ws["attributes"].get("auto-apply")
            
            # Workspace specific permissions/metadata if available
            permissions = ws["attributes"].get("permissions", {})
            can_update = permissions.get("can-update", False)
            
            print(f"\n    [+] Workspace: {ws_name}")
            print(f"        - Terraform version: {tf_version}")
            print(f"        - Auto-apply: {auto_apply}")
            print(f"        - Can Update: {can_update}")

            # Variables (Terraform + Environment)
            print("        [*] Variables:")
            vars_list = api_get(f"{BASE_URL}/workspaces/{ws_id}/vars", headers)

            for var in vars_list:
                key = var["attributes"]["key"]
                value = var["attributes"].get("value")
                category = var["attributes"]["category"]  # terraform or env
                sensitive = var["attributes"]["sensitive"]
                
                # If sensitive, value might be null/None from API
                display_value = value if value is not None else "<sensitive/null>"
                print(f"            - {key} = {display_value} (type: {category}, sensitive: {sensitive})")

            # Runs
            print("        [*] Runs:")
            runs = api_get(f"{BASE_URL}/workspaces/{ws_id}/runs", headers)
            for run in runs[:5]:  # limit output
                status = run["attributes"]["status"]
                created = run["attributes"]["created-at"]
                print(f"            - {status} ({created})")

            # Current State Version metadata
            print("        [*] Current State Version:")
            r = requests.get(f"{BASE_URL}/workspaces/{ws_id}/current-state-version", headers=headers)
            if r.status_code == 200:
                state_data = r.json().get("data")
                if state_data:
                    state_id = state_data['id']
                    download_url = state_data["attributes"].get("hosted-state-download-url")
                    print(f"            - State ID: {state_id}")
                    
                    if download_url:
                        try:
                            # Create states directory if not exists
                            if not os.path.exists("states"):
                                os.makedirs("states")
                            
                            # Download state
                            # Note: The download URL might require auth if it's a direct API link,
                            # but if it redirects to S3/GCS, requests should strip auth on domain change.
                            state_resp = requests.get(download_url, headers=headers, allow_redirects=True)
                            
                            # If 401/403 with headers, try without (in case it was a signed URL that rejected auth)
                            if state_resp.status_code in [401, 403]:
                                state_resp = requests.get(download_url, allow_redirects=True)

                            if state_resp.status_code == 200:
                                state_filename = f"states/{ws_name}_{state_id}.json"
                                with open(state_filename, "wb") as f:
                                    f.write(state_resp.content)
                                print(f"            - State downloaded to: {state_filename}")
                                
                                # Try to parse and extract root outputs
                                try:
                                    state_json = state_resp.json()
                                    outputs = state_json.get("outputs", {})
                                    if outputs:
                                        print("            [*] State Outputs (Potentially Sensitive):")
                                        for out_key, out_val in outputs.items():
                                            val = out_val.get("value")
                                            sensitive = out_val.get("sensitive", False)
                                            print(f"                - {out_key} = {val} (sensitive: {sensitive})")
                                    else:
                                        print("            - No outputs found in state.")
                                except Exception as e:
                                    print(f"            [!] Failed to parse state JSON: {e}")
                            else:
                                print(f"            [!] Failed to download state: {state_resp.status_code}")
                        except Exception as e:
                            print(f"            [!] Error processing state: {e}")
            else:
                print(f"    [!] Request failed: {r.status_code} - {r.text[:100]}")

            time.sleep(0.2)  # polite rate limiting


def main():
    if len(sys.argv) != 2:
        print("Usage: python tfc_enum.py tokens.txt")
        sys.exit(1)

    # Setup logging to both console and file
    sys.stdout = TeeLogger(OUTPUT_FILE)

    token_file = sys.argv[1]

    processed_hashes = load_processed_hashes()
    
    with open(token_file, "r") as f:
        tokens = [line.strip() for line in f if line.strip()]

    print(f"[*] Starting enumeration. Output saved to {OUTPUT_FILE}")
    print(f"[*] Resuming from {RESUME_FILE} ({len(processed_hashes)} processed tokens)")

    for token in tokens:
        token_hash = get_token_hash(token)
        if token_hash in processed_hashes:
            # Uncomment to see skipped tokens
            # print(f"[-] Skipping processed token: {token[:10]}...")
            continue
        
        try:
            enumerate_token(token)
            save_processed_hash(token_hash)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error processing token {token[:10]}...: {e}")
            # Optionally continue to next token or stop? 
            # Usually safer to continue unless it's a critical error



if __name__ == "__main__":
    main()
