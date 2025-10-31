from threading import Thread

from inspect import getsource
from utils.download import download
from utils import get_logger
import scraper
import time


class Worker(Thread):
    def __init__(self, worker_id, config, frontier):
        self.logger = get_logger(f"Worker-{worker_id}", "Worker")
        self.config = config
        self.frontier = frontier
        # basic check for requests in scraper
        assert {getsource(scraper).find(req) for req in {"from requests import", "import requests"}} == {-1}, "Do not use requests in scraper.py"
        assert {getsource(scraper).find(req) for req in {"from urllib.request import", "import urllib.request"}} == {-1}, "Do not use urllib.request in scraper.py"
        super().__init__(daemon=True)
        
    def run(self):
        while True:
            tbd_url = self.frontier.get_tbd_url()
            if not tbd_url:
                self.logger.info("Frontier is empty. Stopping Crawler.")
                break
            resp = download(tbd_url, self.config, self.logger)
            self.logger.info(
                f"Downloaded {tbd_url}, status <{resp.status}>, "
                f"using cache {self.config.cache_server}.")
            scraped_urls = scraper.scraper(tbd_url, resp)
            for scraped_url in scraped_urls:
                self.frontier.add_url(scraped_url)
            self.frontier.mark_url_complete(tbd_url)
            time.sleep(self.config.time_delay)
        
        visited_urls, wordCounts, longestPage, subdomainCounts = scraper.metrics['uniquePages'], scraper.metrics['wordCounts'], scraper.metrics['longestPage'], scraper.metrics['subdomainCounts']
        top_50 = self.get_top_50_words(scraper.get_Count_Frequencies())

        print("Total unique URL's visited:", visited_urls)
        print("Top 50 words:", top_50)
        print("Longest page visited:", longestPage)
        print("Subdomain counts:", subdomainCounts)
    
    def get_top_50_words(self, frequencies):
        return heapq.nlargest(50, frequencies.items(), key=lambda x: x[1])
