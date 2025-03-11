
import pytest

from unittest.mock import patch

from fanficfare.adapters.adapter_wwwsofurrycom import WWWSoFurryComAdapter as sofurrycom
from fanficfare.exceptions import AdultCheckRequired
from fanficfare.epubutils import make_soup

from tests.adapters.generic_adapter_test import GenericAdapterTestExtractChapterUrlsAndMetadata, GenericAdapterTestGetChapterText
from tests.conftest import wwwsofurrycom_html_metadata_initial_return, wwwsofurrycom_html_metadata_part1_return, wwwsofurrycom_html_metadata_part2_return, wwwsofurrycom_html_chapter_return, wwwsofurrycom_html_adultcheck_return

SPECIFIC_TEST_DATA_1 = {
    'adapter': sofurrycom,
    'url': 'https://www.sofurry.com/view/2204686',
    'sections': ["www.sofurry.com"],
    'specific_path_adapter': 'adapter_wwwsofurrycom.WWWSoFurryComAdapter',

    'title': 'Impure',
    'author': 'Of The Wilds',
    'authorId': '99946',
    'dateUpdated': '2024-11-29',
    'expected_chapters': {
        0:   {'title': 'Impure - Chapter Two',
              'url': 'https://www.sofurry.com/view/2204686'},
    },
    'list_chapters_fixture': wwwsofurrycom_html_metadata_initial_return,

    'chapter_url': 'https://www.sofurry.com/view/2204686',
    'expected_sentences': [
        "Argos sat at the elegant",
        "An anxious, religious cheetah",
        "\"Ain\'t you supposed to",
        "again. The wolf was already"
    ],
    'chapter_fixture': wwwsofurrycom_html_metadata_initial_return,

    'datePublished': '2024-11-29',
    'status': 'Completed',
    'language': 'English',
    'genre': 'Bisexual, Canine, Character Development, Cheetah, Coyote, Fantasy, Feline, Fox, Gay, Gnoll, Human, Kobold, M/M, Plot Development, Steampunk, Vixen, Wolf',
    'unofficialGenre': 'Fantasy novel, Forbidden Love, Gay Relationship, Religion, Taboo, airship',
    'views': '427',
    'faves': '12',
    'comments': '2',
    'votes': '17',
    'numChapters': 1,
}

class TestExtractChapterUrlsAndMetadataOneShot(GenericAdapterTestExtractChapterUrlsAndMetadata):
    def setup_method(self):
        self.expected_data = SPECIFIC_TEST_DATA_1

        super().setup_method(
            SPECIFIC_TEST_DATA_1['adapter'],
            SPECIFIC_TEST_DATA_1['url'],
            SPECIFIC_TEST_DATA_1['sections'],
            SPECIFIC_TEST_DATA_1['specific_path_adapter'],
            SPECIFIC_TEST_DATA_1['list_chapters_fixture'])

        self.configuration.validEntries.extend(['views', 'faves', 'comments', 'votes', 'unofficialGenre'])

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch(f'fanficfare.adapters.{self.path_adapter}.get_request') as mockget_request:

            self.adapter.entire_folder = False

            self.mockget_request = mockget_request
            self.mockget_request.return_value = self.fixture

            yield

    def test_get_published_date(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('datePublished') == self.expected_data['datePublished']

    def test_get_status(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('status') == self.expected_data['status']

    def test_get_genre(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('genre') == self.expected_data['genre']

    def test_get_stats(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('views') == self.expected_data['views']
        assert self.adapter.story.getMetadata('faves') == self.expected_data['faves']
        assert self.adapter.story.getMetadata('comments') == self.expected_data['comments']
        assert self.adapter.story.getMetadata('votes') == self.expected_data['votes']

    def test_get_unofficial_genre(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('unofficialGenre') == self.expected_data['unofficialGenre']

    def test_get_numChapters(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert len(self.adapter.get_chapters()) == self.expected_data['numChapters']

    def test_get_novel_intro(self):
        pass

class TestGetChapterTextOneShot(GenericAdapterTestGetChapterText):
    def setup_method(self):
        self.expected_data = SPECIFIC_TEST_DATA_1

        super().setup_method(
            SPECIFIC_TEST_DATA_1['adapter'],
            SPECIFIC_TEST_DATA_1['url'],
            SPECIFIC_TEST_DATA_1['sections'],
            SPECIFIC_TEST_DATA_1['specific_path_adapter'],
            SPECIFIC_TEST_DATA_1['chapter_fixture'])

SPECIFIC_TEST_DATA_2 = {
    'adapter': sofurrycom,
    'url': 'https://www.sofurry.com/view/2204686',
    'sections': ["www.sofurry.com"],
    'specific_path_adapter': 'adapter_wwwsofurrycom.WWWSoFurryComAdapter',

    'title': 'Impure',
    'author': 'Of The Wilds',
    'authorId': '99946',
    'dateUpdated': '2025-03-09',
    'expected_chapters': {
        0:   {'title': 'Impure - Chapter One',
              'url': 'https://www.sofurry.com/view/2204577'},
        8:  {'title': 'Impure - Chapter Nine',
              'url': 'https://www.sofurry.com/view/2225078'},
        11: {'title': 'Impure - Chapter Twelve',
              'url': 'https://www.sofurry.com/view/2232902'},
    },
    'list_chapters_fixture': [wwwsofurrycom_html_metadata_initial_return, wwwsofurrycom_html_metadata_part1_return, wwwsofurrycom_html_metadata_part2_return],

    'chapter_url': 'https://www.sofurry.com/view/2207299',
    'expected_sentences': [
        "Rivi busied himself best he could",
        "Rivimirous whirled around to the",
        "\"I got both.\" Argos offered him",
        "\"That's it?\" Rivi retrieved his"
    ],
    'chapter_fixture': wwwsofurrycom_html_chapter_return,

    'datePublished': '2024-11-28',
    'status': 'Completed',
    'language': 'English',
    'genre': 'Anthro, Bisexual, Canine, Character Development, Cheetah, Coyote, Drama, Fantasy, Feline, Fox, Gay, Gnoll, Human, Humor, Kobold, M/M, Plot Development, Relationships, Steampunk, Vixen, Wolf',
    'unofficialGenre': 'Closeted, Fantasy novel, First love, Forbidden Love, Gay Relationship, Kindness, Plot Progression, Religion, Story Development, Taboo, Writeathon, airship, anxiety, courage, queer',
    'views': '1879',
    'faves': '45',
    'comments': '12',
    'votes': '50',
    'numChapters': 12,
}

class TestExtractChapterUrlsAndMetadataFolder(GenericAdapterTestExtractChapterUrlsAndMetadata):
    def setup_method(self):
        self.expected_data = SPECIFIC_TEST_DATA_2

        super().setup_method(
            SPECIFIC_TEST_DATA_2['adapter'],
            SPECIFIC_TEST_DATA_2['url'],
            SPECIFIC_TEST_DATA_2['sections'],
            SPECIFIC_TEST_DATA_2['specific_path_adapter'],
            SPECIFIC_TEST_DATA_2['list_chapters_fixture'])

        self.configuration.validEntries.extend(['views', 'faves', 'comments', 'votes', 'unofficialGenre'])

    @pytest.fixture(autouse=True)
    def setup_env(self):
        with patch(f'fanficfare.adapters.{self.path_adapter}.get_request') as mockget_request:

            self.adapter.entire_folder = True

            self.mockget_request = mockget_request
            self.mockget_request.side_effect = self.fixture

            yield

    def test_get_published_date(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('datePublished') == self.expected_data['datePublished']

    def test_get_status(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('status') == self.expected_data['status']

    def test_get_genre(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('genre') == self.expected_data['genre']

    def test_get_stats(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('views') == self.expected_data['views']
        assert self.adapter.story.getMetadata('faves') == self.expected_data['faves']
        assert self.adapter.story.getMetadata('comments') == self.expected_data['comments']
        assert self.adapter.story.getMetadata('votes') == self.expected_data['votes']

    def test_get_unofficial_genre(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert self.adapter.story.getMetadata('unofficialGenre') == self.expected_data['unofficialGenre']

    def test_get_numChapters(self):
        # When
        self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert len(self.adapter.get_chapters()) == self.expected_data['numChapters']

    def test_get_novel_intro(self):
        pass

    @patch(f'fanficfare.adapters.adapter_wwwsofurrycom.WWWSoFurryComAdapter.get_request')
    def test_raises_adult_check(self, mockget_request):
        # Given
        mockget_request.return_value = wwwsofurrycom_html_adultcheck_return

        # When
        with pytest.raises(AdultCheckRequired) as exc_info:
            self.adapter.extractChapterUrlsAndMetadata()

        # Then
        assert str(exc_info.value) == "Story requires confirmation of adult status: (https://www.sofurry.com/view/2204686)"

class TestGetChapterTextFolder(GenericAdapterTestGetChapterText):
    def setup_method(self):
        self.expected_data = SPECIFIC_TEST_DATA_2

        super().setup_method(
            SPECIFIC_TEST_DATA_2['adapter'],
            SPECIFIC_TEST_DATA_2['url'],
            SPECIFIC_TEST_DATA_2['sections'],
            SPECIFIC_TEST_DATA_2['specific_path_adapter'],
            SPECIFIC_TEST_DATA_2['chapter_fixture'])