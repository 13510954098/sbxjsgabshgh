"""Offline tests invoking actual extracted Kotlin code, never external sources."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
import evaluate_quality as q
from animeko_engine import Engine, EngineError

CONFIG = {
    'searchUrl': 'https://site.example/search?q={keyword}',
    'subjectFormatId': 'a', 'selectorSubjectFormatA': {'selectLists': 'h3 > a'},
    'channelFormatId': 'index-grouped',
    'selectorChannelFormatFlattened': {'selectChannelNames': '.tab', 'selectEpisodeLists': '.list',
        'selectEpisodesFromList': 'a', 'matchChannelName': '(?<ch>快看).*',
        'matchEpisodeSortFromName': '第\\s*(?<ep>.+)\\s*[话集]'},
    'matchVideo': {'enableNestedUrl': False, 'matchVideoUrl': r'https://cdn\.example/.*\.m3u8(?:\?.*)?'}
}
class ExtractedEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine(os.environ['ANIMEKO_ENGINE_JAR'])
    def setUp(self):
        self.old = q.ENGINE
        q.ENGINE = self.engine
        self.engine.headers.clear()
    def tearDown(self):
        q.ENGINE = self.old
    def test_real_jsoup_and_title_attribute(self):
        c = copy.deepcopy(CONFIG)
        c['selectorSubjectFormatA']['selectLists'] = 'h3:has(a) > a:eq(0)'
        rows = self.engine.subjects(b'<h3><a title="Title" href="/detail">wrong text</a></h3>', c, 'https://site.example/search')
        self.assertEqual(rows, [{'name': 'Title', 'url': 'https://site.example/detail'}])
    def test_real_jsonpath_does_not_search_unrelated_keys(self):
        c = copy.deepcopy(CONFIG)
        c.update(subjectFormatId='json-path-indexed', rawBaseUrl='https://site.example/video/',
                 selectorSubjectFormatJsonPathIndexed={'selectNames':'$.data.videos[*].name','selectLinks':'$.data.videos[*].slug'})
        page = json.dumps({'ad':{'name':'FAKE','slug':'bad'},'data':{'videos':[{'name':'A < B & C','slug':'real'}]}}).encode()
        rows = self.engine.subjects(page, c, 'https://site.example/search')
        self.assertEqual(rows, [{'name':'A < B & C','url':'https://site.example/video/real'}])
    def test_channel_regex_filters_unmatched(self):
        page = '<span class="tab">广告</span><span class="tab">快看1080</span><div class="list"><a href="/ad">第1集</a></div><div class="list"><a href="/good">第2集</a></div>'.encode()
        rows = self.engine.episodes(page, CONFIG, 'https://site.example/detail')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['channel'],'快看')
        self.assertEqual(rows[0]['url'],'https://site.example/good')
        self.assertEqual(rows[0]['episodeSort'],'02')
    def test_episode_separate_link_selector(self):
        c = copy.deepcopy(CONFIG)
        c.update(channelFormatId='no-channel',selectorChannelFormatNoChannel={'selectEpisodes':'.ep','selectEpisodeLinks':'a','matchEpisodeSortFromName':''})
        rows = self.engine.episodes(b'<span class="ep">1</span><a href="/one"></a>',c,'https://site.example/show')
        self.assertEqual(rows[0]['url'],'https://site.example/one')
    def test_video_named_group_and_empty_referer(self):
        c = copy.deepcopy(CONFIG)
        c['matchVideo']['matchVideoUrl'] = r'url=(?<v>https://cdn\.example/[^&]+)'
        c['matchVideo']['cookies'] = 'sensitive-page-cookie'
        rows = self.engine.match(['https://parser.example/?url=https://cdn.example/a.m3u8'],c)
        self.assertEqual(rows[0]['url'],'https://cdn.example/a.m3u8')
        headers = q.media_headers(c,'https://page.example','https://cdn.example/a.m3u8')
        self.assertEqual(headers['Referer'],'')
        self.assertNotIn('Cookie',headers)
    def test_nested_takes_precedence(self):
        c = copy.deepcopy(CONFIG)
        c['matchVideo'].update(enableNestedUrl=True,matchNestedUrl='nested')
        rows = self.engine.match(['https://cdn.example/nested.m3u8'],c)
        self.assertEqual(rows[0]['kind'],'nested')
    def test_suffix_cannot_override_client_matcher(self):
        media, _ = q.static_media_urls(b'<source src="https://ad.example/ad.mp4">','https://site.example/play',CONFIG)
        self.assertEqual(media,[])
    def test_invalid_regex_is_not_fallback_success(self):
        c = copy.deepcopy(CONFIG); c['matchVideo']['matchVideoUrl']='['
        with self.assertRaises(EngineError): self.engine.match(['https://cdn.example/a.m3u8'],c)
    def test_timeout_is_bounded(self):
        with patch('animeko_engine.subprocess.run',side_effect=subprocess.TimeoutExpired('java',12)):
            with self.assertRaises(EngineError): self.engine.call('health')
    def test_private_extracted_target_rejected(self):
        c = copy.deepcopy(CONFIG);c['matchVideo']['matchVideoUrl']='.*'
        media, _ = q.static_media_urls(b'<source src="http://127.0.0.1/a.mp4">','https://site.example',c)
        self.assertEqual(media,[])
    def test_http_200_html_is_not_video(self):
        url='https://cdn.example/a.mp4'
        fetch=q.FakeFetcher({url:q.FetchResult(True,url,200,b'<html>Login</html>','text/html')})
        self.assertFalse(q.probe_media(fetch,url,{})['ok'])
    def test_bad_hls_signature(self):
        url='https://cdn.example/a.m3u8'
        fetch=q.FakeFetcher({url:q.FetchResult(True,url,200,b'fake.ts','application/octet-stream')})
        self.assertEqual(q.probe_media(fetch,url,{})['error'],'invalid-hls-signature')
    def test_html_segment_not_success(self):
        url='https://cdn.example/a.m3u8';seg='https://cdn.example/seg.ts'
        fetch=q.FakeFetcher({url:q.FetchResult(True,url,200,b'#EXTM3U\n#EXTINF:10,\nseg.ts\n','application/vnd.apple.mpegurl'),seg:q.FetchResult(True,seg,200,b'<html>Denied</html>','text/html')})
        self.assertFalse(q.probe_media(fetch,url,{})['ok'])
    def test_final_redirect_url_resolves_hls_segments(self):
        url='https://cdn.example/a.m3u8'; final='https://other.example/live/b.m3u8?key=secret';seg='https://other.example/live/seg.ts'
        fetch=q.FakeFetcher({url:q.FetchResult(True,url,200,b'#EXTM3U\n#EXTINF:10,\nseg.ts\n','application/vnd.apple.mpegurl',final_url=final),seg:q.FetchResult(True,seg,206,b'\x47'+b'\0'*187,'video/mp2t')})
        result=q.probe_media(fetch,url,{})
        self.assertTrue(result['ok']);self.assertNotIn('secret',json.dumps(result))
    def fixture(self, browser_only=False, wrong_title=False):
        item={'factoryId':'web-selector','version':2,'arguments':{'name':'Fixture','description':'','iconUrl':'','tier':3,'searchConfig':copy.deepcopy(CONFIG)}}
        query=q.source_query('Fixture',q.source_identity(item),'2026-10-05')
        url=q.build_search_url(CONFIG,query)
        title='not the title' if wrong_title else query
        responses={
            url:q.FetchResult(True,url,200,f'<h3><a href="/show">{title}</a></h3>'.encode(),'text/html',10),
            'https://site.example/show':q.FetchResult(True,'https://site.example/show',200,'<span class="tab">快看</span><div class="list"><a href="/play">第1集</a></div>'.encode(),'text/html',10),
            'https://site.example/play':q.FetchResult(True,'https://site.example/play',200,b'<script>dynamicVideo()</script>' if browser_only else b'<source src="https://cdn.example/a.m3u8">','text/html',10),
            'https://cdn.example/a.m3u8':q.FetchResult(True,'https://cdn.example/a.m3u8',200,b'#EXTM3U\n#EXTINF:10,\nseg.ts\n','application/vnd.apple.mpegurl',10),
            'https://cdn.example/seg.ts':q.FetchResult(True,'https://cdn.example/seg.ts',206,b'\x47'+b'\0'*187,'video/mp2t',10),
        }
        return q.evaluate_source(item,q.FakeFetcher(responses),today='2026-10-05')
    def test_integrated_pipeline_uses_real_engine(self):
        result=self.fixture()
        self.assertEqual(result['stages']['transportProbe'],'passed')
        self.assertFalse(result['realPlaybackVerified'])
        self.assertEqual(result['engineMethod'],q.ENGINE_METHOD)
    def test_browser_required_is_inconclusive_not_dead(self):
        result=self.fixture(browser_only=True)
        self.assertEqual(result['stages']['videoResolve'],'unknown')
        self.assertFalse(result['eligibleForTierRecommendation'])
    def test_wrong_subject_not_sampled(self):
        result=self.fixture(wrong_title=True)
        self.assertEqual(result['stages']['titleMatch'],'unknown')
        self.assertNotIn('episodeParse',result['stages'])
        self.assertFalse(result['eligibleForTierRecommendation'])
    def test_latest_inconclusive_blocks_old_recommendation(self):
        history=[{'configFingerprint':'f','engineMethod':q.ENGINE_METHOD,'testedAt':f'2026-10-0{i}T00:00:00Z','score':100,'stages':{'transportProbe':'passed'},'eligibleForTierRecommendation':True} for i in range(1,4)]
        history.append({'configFingerprint':'f','engineMethod':q.ENGINE_METHOD,'testedAt':'2026-10-04T00:00:00Z','score':20,'stages':{},'eligibleForTierRecommendation':False})
        self.assertFalse(q.recommendation(history,'f')['ready'])
    def test_inconclusive_report_valid(self):
        result=self.fixture(browser_only=True)
        self.assertEqual(result['quality'],'inconclusive')
        self.assertTrue(q.validate_observation(result))
    def test_generic_bytes_not_a_media_file(self):
        url='https://cdn.example/a.mp4'
        fetch=q.FakeFetcher({url:q.FetchResult(True,url,200,b'not media','application/octet-stream')})
        self.assertFalse(q.probe_media(fetch,url,{})['ok'])
    def test_legacy_observations_not_reused(self):
        history=[{'configFingerprint':'f','testedAt':f'2026-10-0{i}T00:00:00Z','score':100,'stages':{'transportProbe':'passed'}} for i in range(1,4)]
        self.assertFalse(q.recommendation(history,'f')['ready'])

if __name__=='__main__': unittest.main()
