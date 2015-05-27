# -*- coding: utf-8 -*-
"""Setup tests for this package."""
from maxttor.tokenlogin.testing import MAXTTOR_TOKENLOGIN_INTEGRATION_TESTING  # noqa
from plone import api

import unittest2 as unittest


class TestSetup(unittest.TestCase):
    """Test that maxttor.tokenlogin is properly installed."""

    layer = MAXTTOR_TOKENLOGIN_INTEGRATION_TESTING

    def setUp(self):
        """Custom shared utility setup for tests."""
        self.portal = self.layer['portal']
        self.installer = api.portal.get_tool('portal_quickinstaller')

    def test_product_installed(self):
        """Test if maxttor.tokenlogin is installed with portal_quickinstaller."""
        self.assertTrue(self.installer.isProductInstalled('maxttor.tokenlogin'))

    def test_uninstall(self):
        """Test if maxttor.tokenlogin is cleanly uninstalled."""
        self.installer.uninstallProducts(['maxttor.tokenlogin'])
        self.assertFalse(self.installer.isProductInstalled('maxttor.tokenlogin'))

    def test_browserlayer(self):
        """Test that IMaxttorTokenloginLayer is registered."""
        from maxttor.tokenlogin.interfaces import IMaxttorTokenloginLayer
        from plone.browserlayer import utils
        self.assertIn(IMaxttorTokenloginLayer, utils.registered_layers())
