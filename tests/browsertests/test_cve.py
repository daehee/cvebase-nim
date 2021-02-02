from base import BaseTestCase
from parameterized import parameterized

cves = [
    ['cve/2020/14882', 'CVE-2020-14882', '9.8 / 10', 10, 20, 3]
]

class CveTest(BaseTestCase):
    @parameterized.expand(cves)
    def test_data(self, path, cve_id, severity, pocs_shown_count, pocs_hidden_count, ref_urls_count):
        self.open_cvebase(path)

        self.assert_exact_text(cve_id, '#page-hero > div > div > h1')
        self.assert_exact_text(severity, '#description > div > div:nth-child(2) > span.is-size-5.has-text-weight-bold')

        pocs_shown = self.find_elements('#pocs > li')
        self.assert_equal(len(pocs_shown), pocs_shown_count)

        pocs_hidden = self.find_elements('#pocs-more > li')
        self.assert_equal(len(pocs_hidden), pocs_hidden_count)

        ref_urls = self.find_elements('#references > li')
        self.assert_equal(len(ref_urls), ref_urls_count)
