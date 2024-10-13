from os.path import isfile
from colorama import init, Fore
from favihunter.collectors.collector_functions import process_url, process_urls_file
from favihunter.printers.printing_functions import print_hashes, print_results, presentation
from favihunter.utils.utils import calculate_hashes, calculate_mmh3_hash, clean_tmp_dir, get_parsed_arguments, get_project_version


def main() -> None:
    """
    Manages all the program procedures
    :return: None
    """
    try:
        # defining colorama multiplatform
        init(strip=False)
        presentation()
        get_project_version()
        # defining the argparse object
        args = get_parsed_arguments()
        parser = args.parse_args()
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
                    mmh3_value = calculate_mmh3_hash(data=fp.read())
                favicon_hashes = calculate_hashes(favicon_path=parser.favicon, favicon=parser.favicon, mmh3_value=mmh3_value)
                print_hashes(hashes=favicon_hashes)
                print_results(favicon_hashes_dict=favicon_hashes)
            else:
                print(f"[{Fore.BLUE}INF{Fore.RESET}] The file path {Fore.RED}{parser.urls_file}{Fore.RESET} is invalid")

        else:
            args.print_help()

    except KeyboardInterrupt:
        print(f"\n[{Fore.BLUE}INF{Fore.RESET}] Program manually stopped")
    except Exception as error_:
        print(f"[{Fore.LIGHTRED_EX}ERROR{Fore.RESET}] An error occurred and forced the program to stop: {error_}")
