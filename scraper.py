import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import json

metrics = {
    'uniquePages': set(),
    'wordCounts': dict(),
    'longestPage': {'url': '', 'word_count': 0},
    'subdomainCounts': dict()
}

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []

    # Basic checks to see if the url is valid. Validity is checked through status code and content
    if url is None or resp.status != 200:
        return links
    if not resp.raw_response or not resp.raw_response.content:
        return links

    try:
        htmlContent = resp.raw_response.content.decode('utf-8', errors='ignore')
        soup = BeautifulSoup(htmlContent, 'lxml')

        # Clear out JS and CSS info (style and script tags)
        for script in soup(["script", "style"]):
            script.decompose()
        text = soup.get_text()
        words = re.sub(r'\s+', ' ', text.strip()).split(" ")

        if words and len(words) < 50:
            return links
        unique_words = set(word.lower() for word in words)
        if len(unique_words) < len(words) * 0.1:  # Less than 10% unique words
            return links
        
        clean_words = []
        for word in words:
            cleaned = word.lower().strip('.,!?";()[]{}:')
            if cleaned.isalpha() and len(cleaned) > 2 and cleaned not in {'home', 'page', 'site', 'web', 'www', 'http', 'https', 'html', 'htm'}:
                clean_words.append(cleaned)

        # Extract links from the page
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            if href and not href.startswith('#'):  # Skip fragment-only links
                # Convert relative URLs to absolute URLs
                absolute_url = urljoin(url, href)
                # Remove fragment part for uniqueness
                clean_url = urldefrag(absolute_url)[0]
                if clean_url and clean_url not in links:
                    links.append(clean_url)
        
        # Update metrics
        metrics['uniquePages'].update(link for link in links if is_valid(link))
        for word in clean_words:
            metrics['wordCounts'][word] = metrics['wordCounts'].get(word, 0) + 1
        parsed_url = urlparse(resp.url)
        subdomain = parsed_url.netloc
        metrics['subdomainCounts'][subdomain] = metrics['subdomainCounts'].get(subdomain, 0) + 1
        if len(clean_words) > metrics['longestPage']['word_count']:
            metrics['longestPage'] = {'url': resp.url, 'word_count': len(clean_words)}
        
        print(metrics)
        # json can't serialize sets directly, convert the set to a list first
        serializable_metrics = metrics.copy()
        serializable_metrics['uniquePages'] = list(serializable_metrics['uniquePages'])
        with open("metrics.json", "w") as file:
            json.dump(serializable_metrics, file, indent=4)

    except Exception as e:
        print(f"Error processing {url}: {e}")

    return links

def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)

        if parsed.scheme not in set(["http", "https"]):
            print("Couldn't get the right scheme for ", url)
            return False

        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            print("Blocked by extension filter:", url)
            return False
        
        hostname = parsed.hostname
        if hostname is None:
            print("Couldn't get the hostname for ", url)
            return False
        
        domain_allowed = False
        allowedDomains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
        for domain in allowedDomains:
            if hostname == domain or hostname.endswith(domain):
                domain_allowed = True
                break
        
        if not domain_allowed:
            print("Blocked by domain filter:", url)
            return False
        
        return checkForTraps(url)


    except TypeError:
        print ("TypeError for ", parsed)
        raise

TRAP_WORDS = {"calendar", "session_id"}
MAX_PATHS = 10
MAX_URL_LENGTH = 200

def checkForTraps(url):
    parsed = urlparse(url)
    # print(url)
    parsed_path = parsed.path.lower()
    # print("Checking for traps in path: ")
    # print(parsed_path)

    # Check for trap words
    for trap_word in TRAP_WORDS:
        if trap_word in parsed_path:
            return False
    

    # Check for excessive path segments
    path_segments = parsed_path[1:].split('/')
    if len(path_segments) > MAX_PATHS:
        # print("Too many path segments:", len(path_segments))
        return False

    if len(url) > MAX_URL_LENGTH:
        # print("URL too long:", len(url))
        return False

    return True

p = "https://www.ics.uci.edu/"
print(checkForTraps(p))