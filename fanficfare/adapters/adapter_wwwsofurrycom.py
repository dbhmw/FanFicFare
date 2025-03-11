# -*- coding: utf-8 -*-

# Copyright 2023 FanFicFare team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import absolute_import
from ..htmlcleanup import stripHTML
from .. import exceptions as exceptions
from .base_adapter import BaseSiteAdapter, makeDate
import re
import logging
logger = logging.getLogger(__name__)

def getClass():
    return WWWSoFurryComAdapter

class WWWSoFurryComAdapter(BaseSiteAdapter):
    def __init__(self, config, url):
        BaseSiteAdapter.__init__(self, config, url)

        m = re.match(self.getSiteURLPattern(),url)
        if m:
            self.story.setMetadata('storyId',m.group('id'))
            self._setURL("https://"+self.getSiteDomain()+"/view/"+m.group('id'))
        else:
            raise exceptions.InvalidStoryURL(url, self.getSiteDomain(),  self.getSiteExampleURLs())

        self.username = ""
        self.password = ""
        self.is_adult = self.getConfig("is_adult")
        self.entire_folder = self.getConfig("download_entire_folder", False)
        self.oneshot = None
        self.dateformat = "%d %b %Y %H:%M"
        self.story.setMetadata('siteabbrev','sf')
        self.story.setMetadata('status', 'Completed')
        self.story.setMetadata('language', "English")
        self.story.addToList('category', 'Furry')

    @staticmethod
    def getSiteDomain():
        return 'www.sofurry.com'

    @classmethod
    def getSiteExampleURLs(cls):
        return "https://"+cls.getSiteDomain()+"/view/123456"

    def getSiteURLPattern(self):
        return r"https?://"+re.escape(self.getSiteDomain())+r"/view/(?P<id>\d+)"

    def needToLoginCheck(self, data):
        if 'This submission is only available to registered users. Please login to view it.' in data:
            return True
        else:
            return False

    def performLogin(self, url):
        params = {}
        params['YII_CSRF_TOKEN'] = ''
        if self.password:
            params['LoginForm[sfLoginUsername]'] = self.username
            params['LoginForm[sfLoginPassword]'] = self.password
        else:
            params['LoginForm[sfLoginUsername]'] = self.getConfig("username")
            params['LoginForm[sfLoginPassword]'] = self.getConfig("password")
        params['yt0'] = 'Login'

        loginUrl = 'https://' + self.getSiteDomain() + '/user/login'
        logger.info("Will now login to URL (%s) as (%s)" % (loginUrl, params['LoginForm[sfLoginUsername]']))

        d = self.post_request(loginUrl, params)

        if 'href="/upload" class="button"' not in d :
            logger.info("Failed to login to URL %s as %s" % (loginUrl, params['LoginForm[sfLoginUsername]']))
            raise exceptions.FailedToLogin(url,params['LoginForm[sfLoginUsername]'])

    def setGenre(self, soup):
        logger.debug("== Tags ==")
        genre_raw = soup.find('div', class_='section-title', string='Official Tags').parent.find('div', class_='section-content').find_all('a',{'class': 'sf-tag'},recursive=True)
        for a in genre_raw:
            logger.debug(a.get_text())
            self.story.addToList('genre', a.get_text())

        logger.debug("== Unofficial Tags ==")
        unof_genre_raw = soup.find('div', class_='section-title', string='Unofficial Tags')
        if unof_genre_raw:
            unof_genre_raw = unof_genre_raw.parent.find('div', class_='section-content').find_all('a',{'class': 'sf-tag'},recursive=True)
            for a in unof_genre_raw:
                logger.debug(a.get_text())
                self.story.addToList('unofficialGenre', a.get_text())

    def extractChapterUrlsAndMetadata(self):
        logger.info("url: "+self.url)

        data = self.get_request(self.url,usecache=True)
        if (self.getConfig("always_login") and 'href="/upload" class="button"' not in data) or self.needToLoginCheck(data):
            self.performLogin(self.url)
            data = self.get_request(self.url,usecache=False)

        # Some stories are served with only a warning and adding 'guest' at the end reveals the story
        soup = self.make_soup(data)
        if soup.select_one('.sf-content > p > strong'):
            if not self.is_adult:
                raise exceptions.AdultCheckRequired(self.url)
            url = self.url + '/guest'
            data = self.get_request(url,usecache=True)
            soup = self.make_soup(data)

        self.story.setMetadata('author', soup.select_one('.sf-username.sfTextMedium').get_text())
        self.story.setMetadata('authorUrl', soup.select_one('a#sf-userinfo-outer').get('href'))
        self.story.setMetadata('authorId', re.search(r'\?user=(\d+)',soup.select_one('a#sf-userinfo-outer > img').get('src')).group(1))

        story_folder = soup.select_one('div.section-footer a[href^="/browse/folder/stories"]')
        logger.debug(story_folder)
        logger.debug("Attempt entire folder? [%s]"%self.entire_folder)
        if not story_folder or not self.entire_folder:
            title = soup.select_one('div.section.sf-storyfolder-link > div.section-title-highlight')
            if title == None:
                self.story.setMetadata('title', stripHTML(soup.select_one('span#sfContentTitle')))
            else:
                self.story.setMetadata('title', stripHTML(title))

            self.oneshot = data

            self.setGenre(soup)

            stats_section = soup.find('div', class_='section-title', string='Stats').find_next_sibling('div', class_='section-content').decode_contents()

            raw_date_posted = re.search(r'Posted\s(.+?)<br/>',stats_section)
            chapter_date = makeDate(raw_date_posted.group(1),self.dateformat)
            self.story.setMetadata('datePublished', chapter_date)
            self.story.setMetadata('dateUpdated', chapter_date)

            self.story.setMetadata('views', int(re.search(r'(\d{1,3}(?:,\d{3})*)\sviews?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('faves', int(re.search(r'(\d{1,3}(?:,\d{3})*)\sfav(?:es)?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('comments', int(re.search(r'(\d{1,3}(?:,\d{3})*)\scomments?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('votes', int(re.search(r'(\d{1,3}(?:,\d{3})*)\svotes?<br/>', stats_section).group(1).replace(',','')))

            self.story.setMetadata('numChapters', 1)
            self.add_chapter(soup.select_one('#sfContentTitle').get_text(), self.url)
            logger.debug(soup.select_one('#sfContentTitle').get_text())
            return

        chapters_container = soup.select_one('div.section.sf-storyfolder-link > div.section-title-highlight').parent.find('div', class_='section-content').find_all('div', class_='section-content-list')
        if not chapters_container:
            self.performLogin(self.url)
            soup = self.make_soup(self.get_request(self.url,usecache=False))
            chapters_container = soup.select_one('div.section.sf-storyfolder-link > div.section-title-highlight').parent.find('div', class_='section-content').find_all('div', class_='section-content-list')

        #logger.debug(chapters_container)
        first_url = None
        chapter_url = None
        urls = []
        for chapter_div in chapters_container:
            # Current 'chapter' does not have a link and is just in bold
            if chapter_div.find('strong'):
                chapter_url = self.url
                chapter_title = chapter_div.find('strong').get_text()
            else:
                chapter_a = chapter_div.find('a')
                chapter_url = 'https://' + self.getSiteDomain() + chapter_a.get('href')
                chapter_title = stripHTML(chapter_a)
            first_url = chapter_url if not first_url else first_url
            urls.append(chapter_url)
            self.add_chapter(chapter_title, chapter_url)

        logger.debug(urls)
        logger.debug("First url: [%s]"%first_url)
        logger.debug("Last url: [%s]"%chapter_url)
        logger.debug("Chapters: %s"%len(chapters_container))

        soups = []
        if self.entire_folder == 'metadata':
            for url in urls:
                if url == self.url:
                    soups.append(soup)
                    continue
                soup_chp = self.make_soup(self.get_request(url,usecache=True))
                soups.append(soup_chp)
        else:
            for url in urls:
                if url == self.url:
                    soups.append(soup)
                elif url == first_url or url == chapter_url:
                    soup_chp = self.make_soup(self.get_request(url,usecache=True))
                    soups.append(soup_chp)

        views = 0
        votes = 0
        faves = 0
        comments = 0
        raw_date_posted = None
        for sup in soups:
            stats_section = sup.find('div', class_='section-title', string='Stats').find_next_sibling('div', class_='section-content').decode_contents()

            if raw_date_posted:
                raw_date_updated = re.search(r'Posted\s(.+?)<br/>',stats_section)
            else:
                raw_date_posted = re.search(r'Posted\s(.+?)<br/>',stats_section)
            views += int(re.search(r'(\d{1,3}(?:,\d{3})*)\sviews?<br/>', stats_section).group(1).replace(',',''))
            faves += int(re.search(r'(\d{1,3}(?:,\d{3})*)\sfav(?:es)?<br/>', stats_section).group(1).replace(',',''))
            comments += int(re.search(r'(\d{1,3}(?:,\d{3})*)\scomments?<br/>', stats_section).group(1).replace(',',''))
            votes += int(re.search(r'(\d{1,3}(?:,\d{3})*)\svotes?<br/>', stats_section).group(1).replace(',',''))
            logger.debug(views)

            self.setGenre(sup)

        self._setURL(first_url)
        self.story.setMetadata('title', stripHTML(soup.select_one('div.section.sf-storyfolder-link > div.section-title-highlight')))
        self.story.setMetadata('numChapters', len(chapters_container))
        self.story.setMetadata('datePublished', makeDate(raw_date_posted.group(1),self.dateformat))
        self.story.setMetadata('dateUpdated', makeDate(raw_date_updated.group(1),self.dateformat))
        logger.debug("Posted [%s]"%self.story.getMetadata('datePublished'))
        logger.debug("Updated: [%s]"%self.story.getMetadata('dateUpdated'))
        logger.debug("Unofficial: %s"%self.story.getMetadata('unofficialGenre'))
        logger.debug("Official: %s"%self.story.getMetadata('genre'))

        self.story.setMetadata('views', int(views))
        self.story.setMetadata('faves', int(faves))
        self.story.setMetadata('comments', int(comments))
        self.story.setMetadata('votes', int(votes))
        logger.debug(self.story.getMetadata('views'))
        logger.debug(self.story.getMetadata('faves'))
        logger.debug(self.story.getMetadata('comments'))
        logger.debug(self.story.getMetadata('votes'))

    def getChapterText(self, url):
        logger.debug('Getting chapter '+url)
        if self.oneshot:
            data = self.oneshot
            soup = self.make_soup(data)
        else:
            soup = self.make_soup(self.get_request(url,usecache=True))

        story = soup.new_tag("div", **{'id': 'story'})
        desc = soup.select_one('#sfContentDescription')
        if desc:
            story.append(desc)
        image = soup.select_one('#sfContentImage')
        if image:
            story.append(image)
        chapter = soup.select_one('#sfContentBody')
        if chapter:
            story.append(chapter)
        else:
            logger.info('No chapter text, only image?')
        return self.utf8FromSoup(url,story)

    def before_get_urls_from_page(self,url,normalize):
        if self.getConfig("username") and self.getConfig("always_login"):
            self.performLogin(url)