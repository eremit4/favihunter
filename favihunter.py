from requests import get
from tldextract import extract
from urllib.parse import urlencode
from urllib.request import urlopen
from fake_useragent import UserAgent
from favicon import get as get_favicon
from validators import url as url_validation
from contextlib import closing
from os.path import isdir, isfile
from os import mkdir, listdir, remove
from mmh3 import hash as mmh3_calc
from hashlib import md5 as md5_calc
from base64 import b64encode, encodebytes
from codecs import encode as codec_encode
from prettytable import PrettyTable
from colorama import init, Fore, Style
from argparse import ArgumentParser, HelpFormatter
from traceback import format_exc as print_traceback


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def format_setup(self, action) -> str:
        """
        Performs a format setup of argparse help message
        :param action: string config to be added on the format
        :return: the string to be used on argparse configuration
        """
        if not action.option_strings or action.nargs == 0:
            return super().format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return f", {action.option_strings} {args_string}"


def make_url_tiny(url: str) -> str:
    """
    Converts a long url into a tiny url
    :param url: url to be transformed
    :return: Shortened URL
    """
    request_url = f"http://tinyurl.com/api-create.php?{urlencode({'url':url})}"
    with closing(urlopen(request_url)) as response:
        return response.read().decode("utf-8")


def get_favicon_from_url(url: str) -> dict:
    """
    Receives a url, saves the favicon and calculates the hashes
    :param url: url address
    :return: a dict with the hashes
    """
    header = {
        "User-Agent": UserAgent().random,
        "Accept": "*/*",
        "Accept-Language": "pt - BR, pt;q = 0.8, en - US;q = 0.5, en;q = 0.3",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    possible_favicon, favicon, domain = dict(), str(), extract(url)
    try:
        print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Collecting the favicon from {Style.BRIGHT}{Fore.RED}{url}{Style.NORMAL}")
        possible_favicons = get_favicon(url=url, headers=header, timeout=2)
        for data in possible_favicons:
            if ".ico" in data.url:
                possible_favicon["ico"] = data
            if ".png" in data.url:
                possible_favicon["png"] = data
        if possible_favicon.get("ico"):
            favicon = possible_favicon.get("ico")
        else:
            favicon = possible_favicon.get("png")
        print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Extracting hashes from favicon {Style.BRIGHT}{Fore.RED}{favicon.url}{Style.NORMAL}")
        response = get(url=favicon.url, headers=header, stream=True)
        favicon_data = encodebytes(response.content)
        if response.status_code == 200:
            if not isdir("./tmp"):
                mkdir(path="./tmp")
            favicon_path = f"./tmp/{domain.domain}.{favicon.format}"
            with open(file=favicon_path, mode="wb") as fp:
                for piece in response.iter_content(1024):
                    fp.write(piece)
            with open(file=favicon_path, mode="rb") as fp:
                new_favicon_md5 = md5_calc()
                new_favicon_md5.update(fp.read())
                return {"url": favicon.url, "mmh3": mmh3_calc(favicon_data), "md5": new_favicon_md5.hexdigest()}
        else:
            print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Unable to save favicon from url {Style.BRIGHT}{Fore.RED}{favicon.url}{Style.NORMAL}{Fore.WHITE}: {response.text}")
            return {}
    except Exception:
        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}An error occurred: {repr(print_traceback())}")
        return {}


def print_hashes_table(favicon_hashes_dict=dict, favicons_hashes_list=dict) -> None:
    """
    Shows the results table on the terminal
    :param favicon_hashes_dict: a dict with the hashes of one favicon
    :param favicons_hashes_list: a list storing dictionaries with the hashes of more than one favicon
    :return: None
    """
    def add_row_on_table(engine_dict: dict, hash_dict: dict) -> None:
        """
        Adds a new row to the results table
        :param engine_dict: dict with the engines
        :param hash_dict: dict with the hashes
        :return: None
        """
        if engine_dict["name"] == "FOFA":
            query_encoded = b64encode(s=str(engine_dict["query"].format(hash_dict["mmh3"])).encode())
            sector_table.add_row([f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                                  f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['mmh3'])}{Fore.BLUE}",
                                  f"{Fore.WHITE}{make_url_tiny(url=engine_dict['url'].format(query_encoded.decode()))}{Fore.BLUE}"])
        if engine_dict["name"] == "Censys":
            sector_table.add_row([f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                                  f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['md5'])}{Fore.BLUE}",
                                  f"{Fore.WHITE}{make_url_tiny(url=engine_dict['url'].format(hash_dict['md5']))}{Fore.BLUE}"])
        if engine_dict["name"] == "Criminal IP":
            hex_value_formatted = str(hex(hash_dict["mmh3"])).split("x")[1]
            sector_table.add_row([f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                                  f"{Fore.WHITE}{engine_dict['query'].format(hex_value_formatted)}{Fore.BLUE}",
                                  f"{Fore.WHITE}{make_url_tiny(url=engine_dict['url'].format(hex_value_formatted))}{Fore.BLUE}"])
        if engine_dict["name"] in ["Shodan", "Zoomeye", "ODIN"]:
            sector_table.add_row([f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                                  f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['mmh3'])}{Fore.BLUE}",
                                  f"{Fore.WHITE}{make_url_tiny(url=engine_dict['url'].format(hash_dict['mmh3']))}{Fore.BLUE}"])

    sector_table = PrettyTable()
    sector_table.field_names = ["Engine", "Query", "Query Url"]
    engines = {
        "fofa": {"name": "FOFA", "query": 'icon_hash="{}"', "url": "https://en.fofa.info/result?qbase64={}"},
        "zoomeye": {"name": "Zoomeye", "query": 'iconhash:"{}"', "url": "https://www.zoomeye.org/searchResult?q=iconhash%3A%22{}%22"},
        "shodan": {"name": "Shodan", "query": 'http.favicon.hash:"{}"', "url": "https://www.shodan.io/search?query=http.favicon.hash%3A%22{}%22"},
        "odin": {"name": "ODIN", "query": "services.modules.http.favicon.murmur_hash:{}", "url": "https://getodin.com/search/hosts/services.modules.http.favicon.murmur_hash:{}"},
        "criminalip": {"name": "Criminal IP", "query": "favicon: {}", "url": "https://www.criminalip.io/asset/search?query=favicon%3A+{}"},
        "censys": {"name": "Censys", "query": 'services.http.response.favicons.md5_hash="{}"', "url": 'https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash="{}"'}

    }
    if favicon_hashes_dict:
        for engine in engines.values():
            add_row_on_table(engine_dict=engine, hash_dict=favicon_hashes_dict)
        if favicon_hashes_dict.get("url"):
            print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}These are the hashes and queries for the favicon {Style.BRIGHT}{Fore.RED}{favicon_hashes_dict['url']}{Style.NORMAL}")
        else:
            print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}These are the hashes and queries for the favicon {Style.BRIGHT}{Fore.RED}{favicon_hashes_dict['file']}{Style.NORMAL}")
        print(f"{Style.BRIGHT}{Fore.BLUE}{sector_table.get_string(fields=['Engine', 'Query', 'Query Url'])}")
        return

    if favicons_hashes_list:
        for hashes_dict in favicons_hashes_list:
            for engine in engines.values():
                add_row_on_table(engine_dict=engine, hash_dict=hashes_dict)
            print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}These are the hashes and queries for the favicon {Style.BRIGHT}{Fore.RED}{hashes_dict['url']}{Style.NORMAL}")
            print(f"{Style.BRIGHT}{Fore.BLUE}{sector_table.get_string(fields=['Engine', 'Query', 'Query Url'])}")


def main(args_: ArgumentParser) -> None:
    """
    Manages all the program procedures
    :param args_: arguments from the command line
    :return: None
    """
    parser = args_.parse_args()
    if parser.remove_favicons:
        print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Preparing to clean the local favicon directory")
        if len(listdir(path="./tmp")) == 0:
            print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}The directory is empty")
        for favicon_item in listdir(path="./tmp"):
            remove(path=f"./tmp/{favicon_item}")
            print(f"\t{Fore.BLUE}[{Fore.RED}-{Fore.BLUE}] {Style.BRIGHT}{Fore.RED}{favicon_item}{Style.NORMAL}{Fore.WHITE} removed")

    elif parser.url:
        if url_validation(parser.url):
            favicon_dict = get_favicon_from_url(url=parser.url)
            if favicon_dict.get("mmh3"):
                print_hashes_table(favicon_hashes_dict=favicon_dict)
        else:
            print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Url {Style.BRIGHT}{Fore.RED}{parser.url}{Style.NORMAL}{Fore.WHITE} is invalid")

    elif parser.urls_file:
        if isfile(path=parser.urls_file):
            with open(file=parser.urls_file, mode="r+") as urls:
                for url in urls.readlines():
                    url = url.strip()
                    if url_validation(url):
                        favicon_dict = get_favicon_from_url(url=url)
                        if favicon_dict.get("mmh3"):
                            print_hashes_table(favicon_hashes_dict=favicon_dict)
                    else:
                        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Url {Style.BRIGHT}{Fore.RED}{url}{Style.NORMAL}{Fore.WHITE} is invalid")
        else:
            print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}The file path {Style.BRIGHT}{Fore.RED}{parser.urls_file}{Style.NORMAL}{Fore.WHITE} is invalid")

    elif parser.favicon:
        if isfile(path=parser.favicon):
            print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Extracting hashes from favicon {Style.BRIGHT}{Fore.RED}{parser.favicon}{Style.NORMAL}")
            """
            we need to open the file 2 times to calculate correctly these different hashes.
            otherwise, we'll have additions to the final value 
            """
            with open(file=parser.favicon, mode="rb") as fp:
                new_favicon_md5 = md5_calc()
                new_favicon_md5.update(fp.read())
                md5_value = new_favicon_md5.hexdigest()
            with open(file=parser.favicon, mode="rb") as fp:
                encoded_data = codec_encode(fp.read(), encoding="base64")
                mmh3_value = mmh3_calc(encoded_data)
            favicon_hashes = {
                "file": parser.favicon,
                "mmh3": mmh3_value,
                "md5": md5_value
            }
            print_hashes_table(favicon_hashes_dict=favicon_hashes)
        else:
            print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}The file path {Style.BRIGHT}{Fore.RED}{parser.urls_file}{Style.NORMAL}{Fore.WHITE} is invalid")

    else:
        args_.print_help()


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="", add_help=False, formatter_class=arg_style)
    group_required = args.add_argument_group(title="Options")
    group_required.add_argument("-u", "--url", metavar="<address>", type=str, required=False, help="Receives a url, collects the favicon, and returns the hashes, custom queries, and query URLs into a table.")
    group_required.add_argument("-uf", "--urls-file", metavar="<file path>", type=str, required=False, help="Receives a file path storing URLs, collects the favicon, and returns the hashes, custom queries, and query URLs into a table.")
    group_required.add_argument("-f", "--favicon", metavar="<favicon path>", type=str, required=False, help="Receives the favicon file path and returns the hashes, custom queries, and query URLs into a table.")
    group_required.add_argument("-r", "--remove-favicons", action="store_true", required=False, help="Clean the local favicon directory.")
    group_required = args.add_argument_group(title="Help")
    group_required.add_argument("-h", "--help", action="help", help="Show this help screen.")

    # perform colorama multiplatform
    init(strip=False)
    print(r"""{}{}
    
          _____            .__.__                  __                
        _/ ____\____ ___  _|__|  |__  __ __  _____/  |_  ___________ 
        \   __\\__  \\  \/ /  |  |  \|  |  \/    \   __\/ __ \_  __ \
         |  |   / __ \\   /|  |   Y  \  |  /   |  \  | \  ___/|  | \/
         |__|  (____  /\_/ |__|___|  /____/|___|  /__|  \___  >__|   
                    \/             \/           \/          \/         
         {}[{}>{}] {}Hunting assets on the internet using favicon hashes
         {}[{}>{}] {}By eremit4 and johnk3r                                                                                                        
        {}""".format(Style.BRIGHT, Fore.BLUE, Style.NORMAL, Fore.RED, Fore.BLUE, Fore.WHITE,
                     Fore.BLUE, Fore.RED, Fore.BLUE, Fore.WHITE, Fore.RESET))
    try:
        main(args_=args)
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Program manually stopped")
    except Exception:
        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}An error occurred and forced the program to stop: {repr(print_traceback())}")
