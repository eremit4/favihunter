# Favihunter

> Favicons are small icons in modern web applications that could be very useful for us in our day-to-day hunting activities, especially when we combine these icons with modern search engines to find assets on the internet.

> This project helps security professionals find assets online using favicon hashes through search engines such as:
- [BinaryEdge](https://app.binaryedge.io/services/query)
- [Censys](https://search.censys.io/)
- [Criminal IP](https://www.criminalip.io/) 
- [FOFA](https://en.fofa.info/)
- [Hunter-How](https://hunter.how/)
- [Netlas](https://app.netlas.io)
- [Odin](https://search.odin.io/)
- [Shodan](https://www.shodan.io) 
- [Silent Push](https://explore.silentpush.com) 
- [Validin](https://app.validin.com)
- [Zoomeye](https://www.zoomeye.hk)

## 🛠️  Installation

Optional - Creating a virtualenv before installing the dependencies
> Note: The use of virtual environments is optional, but recommended. In this way, we avoid possible conflicts in different versions of the project's dependencies.
> Learn how to install and use virtualenv according to your OS [here](https://virtualenv.pypa.io/en/latest/)

### Via PyPI (Recommended)

You can install FaviHunter directly from [PyPI](https://pypi.org/project/favihunter/):

```bash
pip install favihunter
```

### Via Source (Using Poetry)

Cloning the project:
```bash
git clone https://github.com/eremit4/favihunter.git
```

Installing the dependencies:
```bash
poetry install
```

## 🕵️‍♂️ Using

Discovering the project capabilities:
```bash
favihunter --help
```

Analyzing a specific URL:
```bash
favihunter --url <url address>
```

Analyzing a file with URLs:
```bash
favihunter --urls <file path>
```

Analyzing a local favicon image:
```bash
favihunter --favicon <file path>
```

Cleaning the favicon local directory:
```bash
favihunter --remove-favicons
```

![](logo/favihunter.gif)
