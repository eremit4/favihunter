from pathlib import Path
from colorama import Fore, Style
from yaml import safe_load
from favihunter.utils.utils import make_url_tiny, convert_fofa_query


def presentation() -> None:
    """
    Function that invokes the project presentation.
    :return: None
    """
    print(r"""{}{}

      _____             __ __                  __                
    _/ ____\____ ___  _|__|  |__  __ __  _____/  |_  ___________ 
    \   __\\__  \\  \/ /  |  |  \|  |  \/    \   __\/ __ \_  __ \
     |  |   / __ \\   /|  |   Y  \  |  /   |  \  | \  ___/|  | \/
     |__|  (____  /\_/ |__|___|  /____/|___|  /__|  \___  >__|   
                \/             \/           \/          \/

    {}""".format(Style.BRIGHT, Fore.LIGHTWHITE_EX, Style.NORMAL))


def print_hashes(hashes: dict) -> None:
    """
    Shows the hashes results on the terminal.
    :param hashes: a dict with the hashes.
    :return: None
    """
    for hash_name, hash_value in hashes.items():
        if hash_name == "favicon":
            continue
        print(f"\t[{Fore.BLUE}{Style.BRIGHT}{hash_name}{Style.NORMAL}{Fore.RESET}] {hash_value}")


def print_results(favicon_hashes_dict: dict) -> None:
    """
    Shows the search engine results on the terminal.
    :param favicon_hashes_dict: a dict with the hashes of one favicon.
    :return: None
    """
    print(f"[{Fore.BLUE}INF{Fore.RESET}] Access the shortened URLs to see results from each search engine")
    yaml_path = Path(__file__).resolve().parent.parent / "engines.yaml"
    with open(yaml_path, mode="r") as engines_yaml:
        engines_data = safe_load(engines_yaml)
        for engine_name, engine_info in engines_data.items():
            name = engine_info["name"]
            hash_key = engine_info["hash"]
            if name == "FOFA":
                query = convert_fofa_query(mmh3_hash=favicon_hashes_dict[hash_key])
                url = engine_info["url"].format(query)
            else:
                url = engine_info["url"].format(favicon_hashes_dict[hash_key])
            print(f"\t[{Fore.LIGHTGREEN_EX}{Style.BRIGHT}{name}{Style.NORMAL}{Fore.RESET}][{Fore.BLUE}{Style.BRIGHT}{hash_key}{Style.NORMAL}{Fore.RESET}] {make_url_tiny(url=url)}")
