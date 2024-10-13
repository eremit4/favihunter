from os.path import isfile
from mmh3 import hash as mmh3_calc
from colorama import init, Fore, Style
from argparse import ArgumentParser, HelpFormatter
from favihunter.utils.utils import calculate_hashes, clean_tmp_dir
from favihunter.collectors.collector_functions import process_url, process_urls_file
from favihunter.printers.printing_functions import print_hashes, print_results


def main(args_: ArgumentParser) -> None:
    """
    Manages all the program procedures
    :param args_: arguments from the command line
    :return: None
    """
    parser = args_.parse_args()
    if parser.remove_favicons:
        clean_tmp_dir()

    elif parser.url:
        process_url(url=parser.url)

    elif parser.urls:
        process_urls_file(file_path=parser.urls)

    elif parser.favicon:
        if isfile(path=parser.favicon):
            print(f"[{Fore.BLUE}INF{Fore.RESET}] Extracting hashes from favicon {parser.favicon}")
            """
            we need to open the file 2 times to calculate correctly these different hashes.
            otherwise, we'll have additions to the final value 
            """
            with open(file=parser.favicon, mode="rb") as fp:
                mmh3_value = mmh3_calc(fp.read())
            favicon_hashes = calculate_hashes(favicon_path=parser.favicon, favicon=parser.favicon,
                                              mmh3_value=mmh3_value)
            print_hashes(hashes=favicon_hashes)
            print_results(favicon_hashes_dict=favicon_hashes)
        else:
            print(f"[{Fore.BLUE}INF{Fore.RESET}] The file path {Fore.RED}{parser.urls_file}{Fore.RESET} is invalid")

    else:
        args_.print_help()


if __name__ == '__main__':
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

    # defining colorama multiplatform
    init(strip=False)
    print(r"""{}

          _____            .__.__                  __                
        _/ ____\____ ___  _|__|  |__  __ __  _____/  |_  ___________ 
        \   __\\__  \\  \/ /  |  |  \|  |  \/    \   __\/ __ \_  __ \
         |  |   / __ \\   /|  |   Y  \  |  /   |  \  | \  ___/|  | \/
         |__|  (____  /\_/ |__|___|  /____/|___|  /__|  \___  >__|   
                    \/             \/           \/          \/         
                                    <by {}eremit4{} and {}johnk3r{}>                                                                                                        
        {}""".format(Style.BRIGHT, Fore.LIGHTRED_EX, Fore.RESET, Fore.BLUE, Fore.RESET, Style.NORMAL))
    try:
        main(args_=args)
    except KeyboardInterrupt:
        print(f"\n[{Fore.BLUE}INF{Fore.RESET}] Program manually stopped")
    except Exception as error_:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] An error occurred and forced the program to stop: {error_}")
