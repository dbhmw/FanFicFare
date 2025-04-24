from __future__ import absolute_import
import re, json, logging

# py2 vs py3 transition
from ..six.moves import http_cookiejar as cl
from .base_adapter import BaseSiteAdapter, makeDate
from .. import exceptions as exceptions
from ..htmlcleanup import stripHTML

logger = logging.getLogger(__name__)


def getClass():
    return InkittComSiteAdapter


class InkittComSiteAdapter(BaseSiteAdapter):
    def __init__(self, config, url):
        BaseSiteAdapter.__init__(self, config, url)

        self.username = "NoneGiven"
        self.password = ""

        a = re.match(self.getSiteURLPattern(), url)

        self._setURL(a.group())
        self.story.setMetadata("storyId", a.group("id"))
        self.story.setMetadata('siteabbrev', self.getSiteAbbrev())
        self.dateformat = "%Y-%m-%dT%H:%M:%S.%fZ"

    @staticmethod
    def getSiteDomain():
        return "www.inkitt.com"

    @classmethod
    def getSiteAbbrev(cls):
        return 'ikt'

    @classmethod
    def getSiteExampleURLs(cls):
        return "https://" + cls.getSiteDomain() + "/stories/123456"

    def getSiteURLPattern(self):
        return (r"https://(?:www\.)?inkitt\.com/stories(?:/\w+)?/(?P<id>\d+)")

    def performLogin(self):
        if self.getConfig('session_cookie') and self.getConfig('credentials_cookie'):
            cookie_data = []
            loaded = 0
            cookie_data.append(self.getConfig('credentials_cookie'))
            cookie_data.append(self.getConfig('session_cookie'))
            for cookie_raw in cookie_data:
                if not cookie_raw:
                    continue
                try:
                    cookie_info = json.loads(cookie_raw)
                    cookie = cl.Cookie(
                        version=0, name=cookie_info["name"], value=cookie_info["value"],
                        port=None, port_specified=False,
                        domain=cookie_info["domain"], domain_specified=True, domain_initial_dot=False,
                        path=cookie_info["path"], path_specified=True,
                        secure=cookie_info["secure"], expires=cookie_info["expirationDate"],
                        discard=not cookie_info["session"], comment=None, comment_url=None,
                        rest={'HttpOnly': cookie_info["httpOnly"], 'SameSite': cookie_info["sameSite"]},
                        rfc2109=False)
                    self.get_configuration().get_cookiejar().set_cookie(cookie)
                    logger.debug("Loaded cookie - %s"%cookie_info["name"])
                    cookie = None
                    loaded += 1
                except KeyError as e:
                    logger.debug("Missing key in cookie data - %s"%e)
                except json.JSONDecodeError as e:
                    logger.debug("JSONDecodeError: Could not decode JSON - %s"%e)
            if loaded < 2:
                raise exceptions.FailedToLogin(self.url, "Login unsuccessful. Missing (%s) cookies"%(2-loaded))
            return True
        else:
            raise exceptions.FailedToLogin(self.url, "Login unsuccessful. Missing cookies")

    def extractChapterUrlsAndMetadata(self, get_cover=True):
        logger.debug("URL: %s", self.url)
        url = self.url
        data = self.get_request(self.url)
        soup = self.make_soup(data)

        if soup.find("div", {"class": "only-for-app-story__title"}):
            raise exceptions.FailedToDownload("Book is exclusively available on the mobile app.")

        if soup.find("div", {"id": "patron-tiers-container"}):
            if soup.find("a", {"data-track-link": "My Profile"}) is None:
                if self.performLogin():
                    soup = self.make_soup(self.get_request(url, usecache=False))
                    if soup.find("div", {"id": "patron-tiers-container"}):
                        raise exceptions.FailedToDownload("Book is only available for patreons of this author.")
            else:
                raise exceptions.FailedToDownload("Book is only available for patreons of this author.")

        try:
            meta = soup.find("script", {"type": "application/ld+json"}).decode_contents()
            book_timestamp = json.loads(meta)

            for script in soup.findAll("script"):
                jsn = re.search(r"globalData.author = (.*?);\n", str(script), re.DOTALL)
                if jsn:
                    author_info = json.loads(jsn.group(1))
                    break
            else:
                raise Exception("The necessary script tag can't be found.")
        except Exception as e:
            raise exceptions.FailedToDownload("The required element is missing! %s" % str(e))

        self.story.setMetadata("title", book_timestamp["headline"])
        self.story.setMetadata("dateUpdated", makeDate(book_timestamp["dateModified"], self.dateformat))
        logger.debug(self.story.getMetadata("dateUpdated"))
        self.story.setMetadata("datePublished", makeDate(book_timestamp["datePublished"], self.dateformat))
        logger.debug(self.story.getMetadata("datePublished"))

        self.story.setMetadata("author", author_info["name"])
        self.story.setMetadata("authorId", author_info["id"])
        self.story.setMetadata("authorUrl", "https://{}/{}".format(self.getSiteDomain(), author_info["username"]))
        logger.debug(self.story.getMetadata("authorId"))

        meta_header = soup.find("header", {"class": "story-header"})

        self.setDescription(url, meta_header.find("p", {"class": "story-summary"}))

        try:
            warns = stripHTML(meta_header.find("p", {"class": "content-labels"}))
            warnings = re.sub("This story contains themes of: ", "", warns).split(", ")
            for warn in warnings:
                self.story.addToList("warnings", warn)
        except:
            pass
        logger.debug(self.story.getMetadata("warnings"))

        book_meta = meta_header.find("div", {"class": "dls"})

        self.story.extendList(
            "genre",
            [stripHTML(genre) for genre in book_meta.findChildren("div", recursive=False)[0]
                .find("dl")
                .findAll("a")
            ],
        )
        logger.debug(self.story.getMetadata("genre"))

        status = stripHTML(book_meta.findChildren("div", recursive=False)[1].find("dd"))
        if status == "Ongoing":
            self.story.setMetadata("status", "In-Progress")
        else:
            self.story.setMetadata("status", status)

        rated = book_meta.findChildren("div", recursive=False)[2].findAll("dd")
        self.story.setMetadata("rating", stripHTML(rated[1]))
        logger.debug(self.story.getMetadata("rating"))

        avg_rating = [
            text.strip()
            for text in rated[0].find_all(string=True, recursive=False)
            if text.strip()
        ]
        if avg_rating[0] != "n/a":
            self.story.setMetadata("averrating", float(avg_rating[0]))
            logger.debug(self.story.getMetadata("averrating"))

        story_note = meta_header.find("div", {"class": "story-author-notes__text"})
        if story_note:
            self.story.setMetadata("storynote", stripHTML(story_note))

        try:
            chap_list = soup.find("ul", class_="nav nav-list chapter-list-dropdown").findAll("li")
            self.story.setMetadata("numChapters", len(chap_list))
            for chapter in chap_list:
                chap_url = "https://" + self.getSiteDomain() + chapter.a["href"]
                self.add_chapter(stripHTML(chapter.a.findAll("span", recursive=False)[1]), chap_url)
        except:
            title = stripHTML(soup.find("h2", {"class": "chapter-head-title"}))
            chapter_url = url + "/chapters/1"
            self.add_chapter(title, chapter_url)
            self.story.setMetadata("numChapters", 1)

        api_call = self.get_request("https://www.inkitt.com/api/stories/" + self.story.getMetadata("storyId"))
        api_res = json.loads(api_call)

        lang_list = {1: "English", 2: "Deutsch", 3: "Français", 4: "Español", 11: "Indonesian"}
        self.story.setMetadata('language', lang_list[api_res["language"]["id"]])
        self.story.setMetadata('langcode', api_res["language"]["locale"])
        logger.debug(self.story.getMetadata("language"))
        if api_res["technical_writing_rating"]:
            self.story.setMetadata('technical_writing_rating', round(api_res["technical_writing_rating"], 1))
        if api_res["writing_style_rating"]:
            self.story.setMetadata('writing_style_rating', round(api_res["writing_style_rating"], 1))
        if api_res["plot_rating"]:
            self.story.setMetadata('plot_rating', round(api_res["plot_rating"], 1))
        logger.debug(self.story.getMetadata("plot_rating"))

        if get_cover:
            try:
                cover_img = soup.find("div", {"class": "story-horizontal-cover"})["data-cover-url"]
                # logger.debug(cover_img)
                self.setCoverImage(url, cover_img)
            except Exception as e:
                logger.debug("No cover: %s" % str(e))

        tag_json = None
        script_tags = soup.find_all('script')
        for script in script_tags:
            tag_json = re.search(r'globalData\.storyPills = (.+?}]);', str(script))
            if tag_json != None:
                tag_dict = json.loads(tag_json.group(1))
                break
        else:
            logger.debug("Couldn't extract the tags")

        if tag_dict:
            for tag in tag_dict:
                #logger.debug(tag)
                self.story.addToList('genre', str(tag['name']))

    def getChapterText(self, url):
        logger.debug("Getting chapter text from: %s" % url)
        soup = self.make_soup(self.get_request(url))

        login_required = soup.find("header", {"class": "login-signup__title"})
        if login_required and stripHTML(login_required) == "Sign into Inkitt to Continue Reading":
            if self.performLogin():
                soup = self.make_soup(self.get_request(url, usecache=False))

        story = soup.find("div", {"id": "chapterText"})
        if story is None:
            raise exceptions.FailedToDownload("Failed to download chapter: %s. The necessary tag is missing." % url)

        login_required = soup.find("header", {"class": "login-signup__title"})
        if login_required and stripHTML(login_required) == "Sign into Inkitt to Continue Reading":
            raise exceptions.FailedToLogin(url, "Login unsuccessful. Outdated cookies?")

        return self.utf8FromSoup(url, story)
