from io import BytesIO
from PIL import Image
from os import listdir, remove
from colorama import Fore, Style
from contextlib import closing
from requests import get
from requests.exceptions import RequestException
from urllib.parse import urlparse, urlencode
from urllib.request import urlopen
from hashlib import md5, sha256
from mmh3 import hash as mmh3_calc
from base64 import b64encode, encodebytes
from argparse import ArgumentParser, HelpFormatter
from importlib.metadata import version, PackageNotFoundError


def get_parsed_arguments() -> ArgumentParser:
    """
    Stores all the arguments received from the terminal using the argparse lib.
    :return: The argument parser object.
    """
    arg_style = lambda prog: HelpFormatter(prog, max_help_position=50, width=100)
    args = ArgumentParser(description="Discover and track internet assets using favicon hashes through search engines.", add_help=False, formatter_class=arg_style)
    group_required = args.add_argument_group(title="Options")
    group_required.add_argument("-u", "--url", metavar="<address>", type=str, dest="url", required=False,
                                help="Receives a URL, collects the favicon, and returns the hashes and the search engine results.")
    group_required.add_argument("-uf", "--urls", metavar="<file path>", type=str, dest="urls", required=False,
                                help="Receives a file path storing URLs, collects the favicons, and returns the hashes and the search engine results.")
    group_required.add_argument("-f", "--favicon", metavar="<favicon path>", type=str, dest="favicon", required=False,
                                help="Receives the local file path of the favicon and returns the hashes and search engine results.")
    group_required.add_argument("-r", "--remove-favicons", action="store_true", dest="remove_favicons", required=False,
                                help="Clean the local favicon directory.")
    group_required = args.add_argument_group(title="Help")
    group_required.add_argument("-h", "--help", action="help", help="Show this help screen.")

    return args


def get_project_version() -> None:
    """
    Get the project version defined in pyproject.toml and compare with PyPI version
    :return: None
    """
    try:
        current_version = version("favihunter")
        response = get(url="https://pypi.org/pypi/favihunter/json", timeout=10)
        response.raise_for_status()
        latest_version = response.json()["info"]["version"]
        if latest_version > current_version:
            print(f"[{Fore.BLUE}INF{Fore.RESET}] Current version: {current_version} ({Fore.LIGHTRED_EX}{Style.BRIGHT}outdated{Fore.RESET}{Style.NORMAL})")
            print(f"[{Fore.LIGHTYELLOW_EX}WRN{Fore.RESET}] Please update the project by running {Fore.LIGHTRED_EX}{Style.BRIGHT}pip install --upgrade favihunter{Fore.RESET}{Style.NORMAL}")
        else:
            print(f"[{Fore.BLUE}INF{Fore.RESET}] Current version: {current_version} ({Fore.LIGHTGREEN_EX}{Style.BRIGHT}latest{Fore.RESET}{Style.NORMAL})")
    except PackageNotFoundError:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Unable to get current project version")
    except RequestException as e:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] Unable to check possible updates: {e}")


def is_valid_url(url: str) -> bool:
    """
    Validates if the given URL is valid.
    :param url: The URL to validate.
    :return: True if the URL is valid, False otherwise.
    """
    parsed_url = urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])


def make_url_tiny(url: str) -> str:
    """
    Converts a long URL into a tiny URL
    :param url: URL to be transformed
    :return: Shortened URL
    """
    request_url = f"http://tinyurl.com/api-create.php?{urlencode({'url':url})}"
    with closing(urlopen(request_url)) as response:
        return response.read().decode("utf-8")


def is_valid_image(favicon_content: bytes, favicon_path: str) -> bool:
    """
    Checks if the favicon downloaded is an image
    :param favicon_content: binary content of favicon downloaded
    :param favicon_path: the favicon local path
    :return: True if the image is valid and False if not
    """
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Checking if the favicon downloaded is a valid image")
    try:
        img = Image.open(BytesIO(favicon_content))
        img.verify()
        return True
    except Exception:
        remove(path=favicon_path)
        return False


def clean_tmp_dir() -> None:
    """
    Clean the /tmp directory
    :return:  None
    """
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Preparing to clean the local favicon directory")
    if len(listdir(path="./tmp")) == 0:
        print(f"[{Fore.BLUE}INF{Fore.RESET}] The directory is empty")
    for favicon_item in listdir(path="./tmp"):
        remove(path=f"./tmp/{favicon_item}")
        print(f"\t[{Fore.BLUE}INF{Fore.RESET}] {favicon_item} removed")


def calculate_hashes(favicon_path: str, favicon: str, mmh3_value: int) -> dict:
    """
    Calculates the MD5, SHA256, and MMH3 hashes for the favicon.
    :param favicon_path: Path to the favicon file.
    :param favicon: Favicon identifier.
    :param mmh3_value: MMH3 hash value.
    :return: A dictionary with the calculated hashes.
    """
    with open(file=favicon_path, mode="rb") as fp:
        content = fp.read()
        new_favicon_md5 = md5()
        new_favicon_sha256 = sha256()
        new_favicon_md5.update(content)
        new_favicon_sha256.update(content)
        return {
            "favicon": favicon,
            "MMH3": mmh3_value,
            "MMH3-HEX": str(hex(mmh3_value)).split("x")[1],
            "MD5": new_favicon_md5.hexdigest(),
            "SHA256": new_favicon_sha256.hexdigest()
        }


def calculate_mmh3_hash(data: bytes) -> int:
    """
    Calculates the MMH3 hash
    :param data:
    :return:
    """
    encoded_data = encodebytes(data)
    return mmh3_calc(encoded_data)


def convert_fofa_query(mmh3_hash: int) -> str:
    """
    Creates a base64 from a mmh3 hash to add FOFA search URL
    :param mmh3_hash: mmh3 hash value
    :return: a ba
    """
    query = f'icon_hash="{mmh3_hash}"'.encode("utf-8")
    encoded_query = b64encode(query)
    return encoded_query.decode("utf-8")
