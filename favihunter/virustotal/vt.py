from pathlib import Path
from colorama import Fore, Style
from urllib.parse import urlparse
from yaml import safe_load, safe_dump
from requests import get, exceptions as requests_exceptions


def get_user_option_to_add_api() -> dict:
    """
    Function to prompt the user to add an API key and continue the process.
    :return: A dict with the API key inputted
    """
    user_option = input(f"[{Fore.LIGHTYELLOW_EX}WRN{Fore.RESET}] Do you want to add the API key and continue the process?(y/n)\n\t[{Fore.LIGHTGREEN_EX}{Style.BRIGHT}>{Fore.RESET}{Style.NORMAL}] ")
    if user_option == "y":
        key = input(f"\t[{Fore.LIGHTGREEN_EX}{Style.BRIGHT}>{Style.NORMAL}{Fore.RESET}] Please, input the API key: ").strip()
        if key:
            return add_vt_api_key(api_key=key)
        else:
            print(f"[{Fore.LIGHTYELLOW_EX}WRN{Fore.RESET}] API key not found")
            print(f"[{Fore.BLUE}INF{Fore.RESET}] Process stopped")
            exit(0)
    else:
        print(f"[{Fore.BLUE}INF{Fore.RESET}] Process stopped")
        exit(0)


def check_vt_in_yaml() -> dict:
    """
    Function that check if exist an API key related to VirusTotal in engines.yaml file
    :return: A dict with the operation status and the key, if it exists in engines.yaml
    """
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Checking VirusTotal API Key")
    engines_yaml = Path(__file__).resolve().parent.parent / "engines.yaml"
    with open(file=engines_yaml, mode="r") as file:
        data = safe_load(file)
    if not data.get("VT"):
        return {"status": False, "key": None}
    else:
        return {"status": True, "key": data.get("VT").get("key")}


def add_vt_api_key(api_key: str) -> dict:
    """
    Function that creates the VirusTotal segmentation in engines.yaml file with the API key
    :param api_key: API key inputted by the user
    :return: A dict with the status operation and the API key
    """
    engines_yaml = Path(__file__).resolve().parent.parent / "engines.yaml"
    try:
        with open(file=engines_yaml, mode="r") as file:
            data = safe_load(file)
        data["VT"] = {"name": "VirusTotal", "key": api_key}
        with open(file=engines_yaml, mode="w") as file:
            safe_dump(data, file)
        print(f"[{Fore.BLUE}INF{Fore.RESET}] API key added in engines.yaml")
        return {"status": True, "key": api_key}
    except Exception as e:
        print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] Error handling engines.yaml file: {e}")
        exit(1)


def submit_domain_and_get_dhash(url: str) -> dict:
    """
    Submits a domain to VirusTotal and retrieves the favicon dhash if available.
    :param url: URL to extract the domain address to be analyzed.
    :return: A dictionary with the status of the request and either the dhash or an error message.
    """
    key_data = check_vt_in_yaml()
    if not key_data["status"]:
        print(f"[{Fore.LIGHTYELLOW_EX}WRN{Fore.RESET}] API key not found")
        key_data = get_user_option_to_add_api()
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Sending domain '{domain}' to VirusTotal")
    try:
        response = get(url=f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": key_data.get("key")})
        if response.status_code == 200:
            dhash = response.json().get("data").get("attributes").get("favicon").get("dhash")
            print(f"[{Fore.BLUE}INF{Fore.RESET}] Extracting hash")
            print(f"\t[{Fore.BLUE}{Style.BRIGHT}DHASH{Fore.RESET}{Style.NORMAL}] {dhash}")
            return {"dhash": dhash, "key": key_data.get("key")}
        else:
            print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] HTTP error submitting domain to VirusTotal: {response.status_code}")
            exit(1)
    except requests_exceptions.RequestException as e:
        print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] Error submitting domain to VirusTotal: {e}")
        exit(1)


def search_domains_on_vt_by_dhash(api_key: str, dhash: str) -> dict:
    """
    Search VirusTotal for domains related to a given favicon dhash using advanced query.
    Handles pagination using the cursor to collect all results and retrieves the number of engines that flagged each domain as malicious.
    Also collects the total number of engines available in VirusTotal.
    :param api_key: VirusTotal API key.
    :param dhash: The favicon dhash to search for.
    :return: A dictionary containing the list of domains with malicious votes and the total number of engines.
    """
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Searching for related domains on VirusTotal using the favicon DHASH")
    domain_results = []
    seen_domains = set()
    total_engines = 0
    params = {"query": f"entity:domain main_icon_dhash:{dhash}"}

    try:
        while True:
            response = get(
                url="https://www.virustotal.com/api/v3/intelligence/search",
                headers={"x-apikey": api_key},
                params=params
            )
            response_data = response.json()

            if response.status_code == 200 and "data" in response_data:
                for item in response_data["data"]:
                    last_analysis = item.get("attributes", {}).get("last_analysis_stats", {})
                    total_engines = sum(last_analysis.values())
                    domain = item.get("id")
                    malicious_votes = item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                    if domain and domain not in seen_domains:
                        domain_results.append({"domain": domain, "malicious_votes": malicious_votes})
                        seen_domains.add(domain)

                cursor = response_data.get("meta", {}).get("cursor")
                if cursor:
                    params["cursor"] = cursor
                else:
                    break
            else:
                print(f"[{Fore.LIGHTYELLOW_EX}WRN{Fore.RESET}] {response.status_code} - {response.text}")
                break

    except requests_exceptions.RequestException as error:
        print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] HTTP error collecting domains through favicon DHASH: {error}")
    except Exception as e:
        print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] Error collecting domains through favicon DHASH: {e}")

    return {"domains": domain_results, "total_engines": total_engines}



def vt_favicon_operation(url: str) -> None:
    """
    Orchestrates the VirusTotal favicon operation.
    Submits the domain, retrieves the favicon dhash, and searches for related domains.
    :param url: The URL to analyze.
    :return: None
    """
    vt_data = submit_domain_and_get_dhash(url=url)
    vt_favicon_results = search_domains_on_vt_by_dhash(api_key=vt_data["key"], dhash=vt_data["dhash"])
    total_findings = len(vt_favicon_results["domains"])
    print(f"[{Fore.BLUE}INF{Fore.RESET}] {total_findings} domains collected")
    if total_findings > 20:
        export_check = input(f"[{Fore.BLUE}INF{Fore.RESET}] Do you want to export the results?(y/n)\n\t[{Fore.LIGHTGREEN_EX}{Style.BRIGHT}>{Fore.RESET}{Style.NORMAL}] ")
        if export_check == "y":
            result_file_path = Path(__file__).resolve().parent.parent.parent / "tmp/favihunter_results.txt"
            try:
                with open(file=result_file_path, mode="w") as fp:
                    fp.writelines(f"{result['domain']}\n" for result in vt_favicon_results['domains'])
                print(f"[{Fore.BLUE}INF{Fore.RESET}] File created successfully")
                print(f"[{Fore.BLUE}INF{Fore.RESET}] Check the results in {result_file_path}")
            except Exception as error:
                print(f"[{Fore.LIGHTRED_EX}ERR{Fore.RESET}] Error creating file with result from VirusTotal: {error}")
        else:
            list_results_in_terminal(vt_results=vt_favicon_results)
    else:
        list_results_in_terminal(vt_results=vt_favicon_results)


def list_results_in_terminal(vt_results: dict) -> None:
    """
    Displays the data collected from VirusTotal.
    :param vt_results: Dict with the data collected from VirusTotal.
    :return: None
    """
    engines = vt_results["total_engines"]
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Displaying results:")
    for idx, result in enumerate(vt_results["domains"], start=1):
        domain = result["domain"]
        votes = f"{Fore.LIGHTRED_EX}{result['malicious_votes']}{Fore.RESET}" if int(result["malicious_votes"]) > 0 else result["malicious_votes"]
        print(f"\t[{Fore.LIGHTGREEN_EX}{Style.BRIGHT}{idx}{Style.NORMAL}{Fore.RESET}] {domain} ({votes}/{engines})")
