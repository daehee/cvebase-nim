from base import BaseTestCase
from parameterized import parameterized

routes = [
    [''],
    ['cve'],
    ['cve/2020'],
    ['cve/2020/m/12'],
    ['cve/2020/14882'],
    ['researcher'],
    ['researcher/orange'],
    ['poc'],
    ['lab'],
    ['bugbounty'],
    ['product/microsoft-windows_xp'],
]

class SmokeTest(BaseTestCase):
    @parameterized.expand(routes)
    def test_routes(self, path):
        self.open_cvebase(path)

        self.assert_element_absent("//h1[contains(text(), '500 Internal Server Error')]", timeout=1)
