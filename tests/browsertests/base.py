# pytest --headless -n 8 --reruns 3 --reruns-delay 2

from seleniumbase import BaseCase

class BaseTestCase(BaseCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()

    def tearDown(self):
        super(BaseTestCase, self).tearDown()

    def open_cvebase(self, page=''):
        self.open(f'http://localhost:6969/{page}')
