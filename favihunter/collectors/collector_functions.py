from os import mkdir
from os.path import isdir, isfile
from typing import List, Optional
from colorama import Fore
from requests import get
from requests.exceptions import RequestException
from urllib.parse import urlparse
from fake_useragent import UserAgent
from favicon import get as get_favicon
from favihunter.printers.printing_functions import print_hashes, print_results
from favihunter.utils.utils import is_valid_image, is_valid_url, calculate_hashes, calculate_mmh3_hash


def get_favicon_from_url(url: str) -> dict:
    """
    Receives a URL, saves the favicon, invokes the functions to calculate the hashes and print the results
    :param url: URL address
    :return: a dict with the hashes
    """
    header = {
        "User-Agent": UserAgent().random,
        "Accept": "*/*",
        "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    try:
        possible_favicons = get_favicon(url=url, headers=header, timeout=2)
        favicon = select_favicon(possible_favicons)
        if not favicon:
            print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] No valid favicon found for {url}")
            return {}

        print(f"[{Fore.BLUE}INF{Fore.RESET}] Favicon {favicon.url} downloaded in /tmp")

        with get(url=favicon.url, headers=header, stream=True) as response:
            if response.status_code != 200:
                print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Unable to save favicon from url {favicon.url}: {response.text}")
                return {}

            mmh3_value = calculate_mmh3_hash(data=response.content)

            if not isdir("./tmp"):
                mkdir(path="./tmp")

            favicon_path = save_favicon(favicon_content=response.content, domain=domain, ext=favicon.format)
            if not is_valid_image(favicon_content=response.content, favicon_path=favicon_path):
                print(
                    f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] The downloaded favicon was not a valid image and has been removed")
                return {}

            print(f"[{Fore.BLUE}INF{Fore.RESET}] Extracting hashes")
            results = calculate_hashes(favicon_path, favicon.url, mmh3_value)
            print_hashes(hashes=results)
            return results

    except RequestException as req_error:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Request error occurred: {req_error}")
    except Exception as error_get_favicon:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] An error occurred: {error_get_favicon}")

    return {}


def select_favicon(favicons: List[object]) -> Optional[object]:
    """
    Selects the preferred favicon format.
    :param favicons: List of favicons with different formats.
    :return: The selected favicon object, if found.
    """
    for data in favicons:
        if ".ico" in data.url:
            return data
    for data in favicons:
        if ".png" in data.url:
            return data
    return None


def save_favicon(favicon_content: bytes, domain: str, ext: str) -> str:
    """
    Saves the favicon to the tmp folder.
    :param favicon_content: Binary content of the favicon.
    :param domain: The domain name.
    :param ext: The favicon format extension.
    :return: The path to the saved favicon.
    """
    favicon_path = f"./tmp/{domain}.{ext}"
    with open(file=favicon_path, mode="wb") as fp:
        fp.write(favicon_content)
    return favicon_path


def process_url(url: str) -> None:
    """
    Checks that the URL is valid and invokes the other operations to get the favicon and print the results.
    :param url: URL to check.
    :return: None
    """
    if is_valid_url(url=url):
        favicon_dict = get_favicon_from_url(url=url)
        if favicon_dict:
            print_results(favicon_hashes_dict=favicon_dict)
    else:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Url {url} is invalid")


def process_urls_file(file_path: str) -> None:
    """
    Checks that the file is valid and collect the URLs to send to the process_url function.
    :param file_path: local file path with URLs.
    :return: None
    """
    try:
        if isfile(path=file_path):
            with open(file=file_path, mode="r+") as urls:
                for url in urls.readlines():
                    if url.strip():
                        process_url(url.strip())
        else:
            print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] The file path {file_path} is invalid")
    except FileNotFoundError:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] File not found: {file_path}")
    except PermissionError:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Permission denied: {file_path}")