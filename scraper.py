import re
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import json
import tokenizer

unique_pages_set = set()
wordCounts = dict()
metrics = {
    'uniquePages': 0,
    'wordCounts': dict(),
    'longestPage': {'url': '', 'word_count': 0},
    'subdomainCounts': dict()
}

def scraper(url, resp):
    print("Scraping:", url)
    links = extract_next_links(url, resp)
    return links

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

        # Use the decoded HTML string for tokenization (tokenizer also accepts bytes,
        # but passing the decoded string is clearer and avoids byte/str surprises)
        for tag in soup(["script", "style"]):
            tag.decompose()

        page_text = soup.get_text(" ", strip=True)
        words = tokenizer.tokenize(page_text)
        frequencies = tokenizer.computeWordFrequencies(words)

        if words and len(words) < 50 or len(frequencies) < len(words) * 0.1:
            return links

        # Extract links from the page
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            if href and not href.startswith('#'):  # Skip fragment-only links
                # Convert relative URLs to absolute URLs
                absolute_url = urljoin(url, href)
                # Remove fragment part for uniqueness
                clean_url = urldefrag(absolute_url)[0]
                if clean_url:
                    links.append(clean_url)
        
        # Only add valid links to unique pages set
        valid_links = [link for link in links if is_valid(link)]
        for link in valid_links:
            unique_pages_set.add(link)

        # Update metrics
        metrics['uniquePages'] = len(unique_pages_set)
        for word, counts in frequencies.items():
            wordCounts[word] = wordCounts.get(word, 0) + counts
        parsed_url = urlparse(resp.url)
        subdomain = parsed_url.netloc
        metrics['subdomainCounts'][subdomain] = metrics['subdomainCounts'].get(subdomain, 0) + 1
        if len(words) > metrics['longestPage']['word_count']:
            metrics['longestPage'] = {'url': resp.url, 'word_count': len(words)}
        
        # print(metrics)
        # json can't serialize sets directly, convert the set to a list first
        # Ensure metrics reflect the up-to-date word counts and make the set
        # of unique pages serializable.
        metrics['wordCounts'] = wordCounts
        serializable_metrics = metrics.copy()
        serializable_metrics['uniquePages'] = list(unique_pages_set)
        with open("metrics.json", "w") as file:
            json.dump(serializable_metrics, file, indent=4)

        write_report()

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
            # print("Couldn't get the right scheme for ", url)
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
            # print("Blocked by extension filter:", url)
            return False
        
        hostname = parsed.hostname
        if hostname is None:
            # print("Couldn't get the hostname for ", url)
            return False
        
        domain_allowed = False
        allowedDomains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
        for domain in allowedDomains:
            if hostname == domain or hostname.endswith(domain):
                domain_allowed = True
                break
        
        if not domain_allowed:
            # print("Blocked by domain filter:", url)
            return False
        
        return checkForTraps(url)


    except TypeError:
        print ("TypeError for ", parsed)
        raise

    except ValueError:
        print ("ValueError for ", parsed)
        raise

TRAP_WORDS = {"calendar", "session_id", "sessionid", "login", "logout", "register", "signin", "signout", "events", "event", "ical", "tribe", "pix"}
MAX_PATHS = 10
MAX_URL_LENGTH = 200
# repeating sequences
# logins, protected websites
# number of redirects
# check for duplicating redirects
# check for near (compare the similarities using a threshold [cosin similarity]) and exact duplicates FOR EC

def checkForTraps(url):
    parsed = urlparse(url)
    parsed_path = parsed.path.lower()

    # Check for trap words
    for trap_word in TRAP_WORDS:
        if trap_word in parsed_path or trap_word in parsed.query:
            return False
        
    # Check for "doku.php" crawler trap
    if "doku.php" in parsed_path:
        return False

    # Check for gitlab and git trap
    if re.search(r'/git(-lab)?/', parsed_path):
        return False
    
    # Check for excessive path segments
    path_segments = parsed_path[1:].split('/')
    if len(path_segments) > MAX_PATHS:
        # print("Too many path segments:", len(path_segments))
        return False

    # Check for excessive URL length
    if len(url) > MAX_URL_LENGTH:
        # print("URL too long:", len(url))
        return False

    return True

def get_Count_Frequencies():
    return wordCounts

def write_report():
    longest_page = metrics['longestPage']
    top_words = sorted(wordCounts.items(), key=lambda item: (-item[1], item[0]))[:50]
    uci_subdomains = sorted(metrics['subdomainCounts'].items())

    report_lines = [
        f"UNIQUE PAGES: {metrics['uniquePages']}",
        f"LONGEST PAGE: {longest_page['url']} ({longest_page['word_count']} words) \n"
    ]

    report_lines.append("TOP 50 WORDS:")
    for word, count in top_words:
        report_lines.append(f"{word}, {count}")
    report_lines.append("\n")

    report_lines.append(f"SUBDOMAINS in uci.edu: {len(uci_subdomains)} \n")
    report_lines.append("SUBDOMAIN, UNIQUE PAGES COUNT")
    for subdomain, count in uci_subdomains:
        report_lines.append(f"{subdomain}, {count}")

    with open("report.txt", "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report_lines) + "\n")