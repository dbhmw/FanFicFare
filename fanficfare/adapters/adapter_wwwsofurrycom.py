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
        self.loggedin = False
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
        else:
            self.loggedin = True

    def extractChapterUrlsAndMetadata(self):
        logger.info("url: "+self.url)

        data = self.get_request(self.url,usecache=True)

        if (self.getConfig("always_login") and 'href="/upload" class="button"' not in data) or 'This submission is only available to registered users. Please login to view it.' in data:
            self.performLogin(self.url)
            data = self.get_request(self.url,usecache=False)

        soup = self.make_soup(data)

        if soup.select_one('.sf-content > p > strong'):
            if self.is_adult:
                url = self.url + '/guest'
                data = self.get_request(url,usecache=True)
                soup = self.make_soup(data)
            else:
                raise exceptions.AdultCheckRequired(self.url)

        title = soup.select_one('div.section.sf-storyfolder-link > div.section-title-highlight')
        if not title:
            title = soup.select_one('span#sfContentTitle')
        self.story.setMetadata('title',title.get_text())

        self.story.setMetadata('author', soup.select_one('.sf-username.sfTextMedium').get_text())
        self.story.setMetadata('authorUrl', soup.select_one('a#sf-userinfo-outer').get('href'))
        self.story.setMetadata('authorId', re.search(r'\?user=(\d+)',soup.select_one('a#sf-userinfo-outer > img').get('src')).group(1))

        story_folder = soup.select_one('div.section-footer a[href^="/browse/folder/stories"]')
        logger.debug('Folder: ' + story_folder.get_text())
        if not story_folder or True: #or ONE_PAGE:self.getConfig("onestory")
            genre_raw = soup.select_one('div.section-content > div.titlehover').find_all('a',{'class': 'sf-tag'},recursive=False)
            for a in genre_raw:
                logger.debug(a.get_text())
                self.story.addToList('genre', a.get_text())

            stats_section = soup.find('div', class_='section-title', string='Stats').find_next_sibling('div', class_='section-content').decode_contents()

            self.story.setMetadata('views', int(re.search(r'(\d{1,3}(?:,\d{3})*)\sviews?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('faves', int(re.search(r'(\d{1,3}(?:,\d{3})*)\sfav(?:es)?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('comments', int(re.search(r'(\d{1,3}(?:,\d{3})*)\scomments?<br/>', stats_section).group(1).replace(',','')))
            self.story.setMetadata('votes', int(re.search(r'(\d{1,3}(?:,\d{3})*)\svotes?<br/>', stats_section).group(1).replace(',','')))

            raw_date_posted = re.search(r'Posted\s(.+?)<br/>',stats_section)
            chapterDate = makeDate(raw_date_posted.group(1),self.dateformat)
            raw_date_mod = re.search(r'Last edited\s(.+?)<br/>',stats_section)
            if not raw_date_mod:
                raw_date_mod = raw_date_posted
            chapterDateMod = makeDate(raw_date_mod.group(1),self.dateformat)

            self.story.setMetadata('datePublished', chapterDate)
            self.story.setMetadata('dateUpdated', chapterDate)

            self.story.setMetadata('numChapters',1)
            self.add_chapter(soup.select_one('#sfContentTitle').get_text(),self.url,
             {'date':chapterDate.strftime(self.getConfig("datechapter_format",self.getConfig("datePublished_format","%Y-%m-%d %H:%M"))),
             'modified':chapterDateMod.strftime(self.getConfig("datechapter_format",self.getConfig("datePublished_format","%Y-%m-%d %H:%M")))})
            logger.debug(soup.select_one('#sfContentTitle').get_text())
            return

        if self.loggedin:
            chapters_container = soup.select_one('div.section-content > div.section-content-list').parent
        ## &stories-display=40
        self.story.setMetadata('numChapters',1)

        
        self.story.addToList('genre',char.string)

        if 'Published' in label:
            self.story.setMetadata('datePublished', makeDate(stripHTML(value), self.dateformat))
            self.story.setMetadata('dateUpdated', makeDate(stripHTML(value), self.dateformat))

    def getChapterText(self, url):
        data = self.get_request(self.url,usecache=True)
        soup = self.make_soup(data)
        story = soup.new_tag("div", **{'id': 'story'})
        desc = soup.select_one('#sfContentDescription')
        if desc:
            story.append(desc)
        image = soup.select_one('#sfContentImage')
        if image:
            story.append(image)
        chapter = soup.select_one('#sfContentBody')
        story.append(chapter)
        return self.utf8FromSoup(url,story)

    def before_get_urls_from_page(self,url,normalize):
        if self.getConfig("username") and self.getConfig("always_login"):
            self.performLogin(url)