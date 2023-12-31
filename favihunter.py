from requests import get
from tldextract import extract
from urllib.parse import urlencode
from urllib.request import urlopen
from fake_useragent import UserAgent
from favicon import get as get_favicon
from validators import url as url_validation
from contextlib import closing
from os.path import isdir
from os import mkdir
from mmh3 import hash as mm3_hash
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
    Converts a long URL into a tiny url
    :param url: url to be transformed
    :return: Tiny URL
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
    domain = extract(url)
    print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Collecting the favicon from {Style.BRIGHT}{Fore.RED}{url}{Style.NORMAL}")
    favicon = get_favicon(url=url, headers=header, timeout=2)
    print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}Extracting hashes from favicon {Style.BRIGHT}{Fore.RED}{favicon[0].url}{Style.NORMAL}")
    response = get(url=favicon[0].url, headers=header, stream=True)
    favicon_data = encodebytes(response.content)
    if response.status_code == 200:
        if not isdir("./tmp"):
            mkdir(path="./tmp")
        with open(file=f"./tmp/{domain.domain}.{favicon[0].format}", mode="wb") as fp:
            for piece in response.iter_content(1024):
                fp.write(piece)
        return {
            "url": favicon[0].url,
            "mm3": mm3_hash(favicon_data),
            "md5": md5_calc(favicon_data).hexdigest()
        }
    else:
        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Unable to save favicon from url {Style.BRIGHT}{Fore.RED}{favicon[0]}{Style.NORMAL}{Fore.WHITE}:\n{response.text}")
        return {}


def print_hashes_table(favicon_hashes_dict=None, favicons_hashes_list=None) -> None:
    """
    Shows the results table on the terminal
    :param favicon_hashes_dict: a dict with the hashes of one favicon
    :param favicons_hashes_list: a list storing dictionaries with the hashes of more than one favicons
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
            query_encoded = b64encode(s=str(engine_dict["query"].format(hash_dict["mm3"])).encode())
            url = engine_dict["url"].format(query_encoded.decode())
            sector_table.add_row(
                [
                    f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                    f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['mm3'])}{Fore.BLUE}",
                    f"{Fore.WHITE}{make_url_tiny(url=url)}{Fore.BLUE}"
                ]
            )
        if engine_dict["name"] == "Censys":
            url = engine_dict["url"].format(hash_dict["md5"])
            sector_table.add_row(
                [
                    f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                    f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['md5'])}{Fore.BLUE}",
                    f"{Fore.WHITE}{make_url_tiny(url=url)}{Fore.BLUE}"
                ]
            )
        if engine_dict["name"] == "Criminal IP":
            hex_value_formatted = str(hex(hash_dict["mm3"])).split("x")[1]
            url = engine_dict["url"].format(hex_value_formatted)
            sector_table.add_row(
                [
                    f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                    f"{Fore.WHITE}{engine_dict['query'].format(hex_value_formatted)}{Fore.BLUE}",
                    f"{Fore.WHITE}{make_url_tiny(url=url)}{Fore.BLUE}"
                ]
            )
        if engine_dict["name"] in ["Shodan", "Zoomeye"]:
            url = engine_dict["url"].format(hash_dict["mm3"])
            sector_table.add_row(
                [
                    f"{Fore.RED}{engine_dict['name']}{Fore.BLUE}",
                    f"{Fore.WHITE}{engine_dict['query'].format(hash_dict['mm3'])}{Fore.BLUE}",
                    f"{Fore.WHITE}{make_url_tiny(url=url)}{Fore.BLUE}"
                ]
            )

    sector_table = PrettyTable()
    sector_table.field_names = ["Engine", "Query", "Query Url"]
    engines = {
        "fofa": {"name": "FOFA", "query": 'icon_hash="{}"', "url": "https://en.fofa.info/result?qbase64={}"},
        "shodan": {"name": "Shodan", "query": 'http.favicon.hash:"{}"', "url": "https://www.shodan.io/search?query=http.favicon.hash%3A%22{}%22"},
        "zoomeye": {"name": "Zoomeye", "query": 'iconhash:"{}"', "url": "https://www.zoomeye.org/searchResult?q=iconhash%3A%22{}%22"},
        "censys": {"name": "Censys", "query": 'services.http.response.favicons.md5_hash="{}"', "url": 'https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash="{}"'},
        "criminalip": {"name": "Criminal IP", "query": "favicon: {}", "url": "https://www.criminalip.io/asset/search?query=favicon%3A+{}"}
    }
    if favicon_hashes_dict is not None:
        for engine in engines.values():
            add_row_on_table(engine_dict=engine, hash_dict=favicon_hashes_dict)
        print(f"{Fore.BLUE}[{Fore.RED}>{Fore.BLUE}] {Fore.WHITE}These are the hashes and queries for the favicon {Style.BRIGHT}{Fore.RED}{favicon_hashes_dict['url']}{Style.NORMAL}")
        print(f"{Style.BRIGHT}{Fore.BLUE}{sector_table.get_string(fields=['Engine', 'Query', 'Query Url'])}")
        return

    if favicons_hashes_list is not None:
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
    if parser.url:
        if url_validation(parser.url):
            print_hashes_table(favicon_hashes_dict=get_favicon_from_url(url=parser.url))
        else:
            print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Url {Style.BRIGHT}{Fore.RED}{parser.url}{Style.NORMAL}{Fore.WHITE} is invalid")
    elif parser.urls_file:
        pass
    elif parser.favicon:
        pass
    else:
        args_.print_help()


if __name__ == '__main__':
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description="", add_help=False, formatter_class=arg_style)
    group_required = args.add_argument_group(title="Options")
    group_required.add_argument("-u", "--url", metavar="<address>", type=str, required=False, help="Receives a url, collects the favicon, and returns the hashes.")
    group_required.add_argument("-uf", "--urls-file", metavar="<file path>", type=str, required=False, help="Receives a file storing a lits of urls, collects the favicons, and returns the hashes.")
    group_required.add_argument("-f", "--favicon", metavar="<favicon path>", type=str, required=False, help="Receives the favicon file path and returns the hashes.")
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
                        {}[{}>{}] {}Hunting assets through favicon hashes
                        {}[{}>{}] {}By eremit4 and johnk3r                                                                                                        
        {}""".format(Style.BRIGHT, Fore.BLUE, Style.NORMAL, Fore.RED, Fore.BLUE, Fore.WHITE,
                     Fore.BLUE, Fore.RED, Fore.BLUE, Fore.WHITE, Fore.RESET))
    try:
        main(args_=args)
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}[{Fore.RED}!{Fore.BLUE}] {Fore.WHITE}Program manually stopped")
    except Exception:
        print(print_traceback())
