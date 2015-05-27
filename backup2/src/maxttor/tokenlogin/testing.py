# -*- coding: utf-8 -*-
from plone.app.robotframework.testing import REMOTE_LIBRARY_BUNDLE_FIXTURE
from plone.app.testing import applyProfile
from plone.app.testing import FunctionalTesting
from plone.app.testing import IntegrationTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.testing import z2
from zope.configuration import xmlconfig

import maxttor.tokenlogin


class MaxttorTokenloginLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        xmlconfig.file(
            'configure.zcml',
            maxttor.tokenlogin,
            context=configurationContext
        )

    def setUpPloneSite(self, portal):
        applyProfile(portal, 'maxttor.tokenlogin:default')


MAXTTOR_TOKENLOGIN_FIXTURE = MaxttorTokenloginLayer()


MAXTTOR_TOKENLOGIN_INTEGRATION_TESTING = IntegrationTesting(
    bases=(MAXTTOR_TOKENLOGIN_FIXTURE,),
    name='MaxttorTokenloginLayer:IntegrationTesting'
)


MAXTTOR_TOKENLOGIN_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(MAXTTOR_TOKENLOGIN_FIXTURE,),
    name='MaxttorTokenloginLayer:FunctionalTesting'
)


MAXTTOR_TOKENLOGIN_ACCEPTANCE_TESTING = FunctionalTesting(
    bases=(
        MAXTTOR_TOKENLOGIN_FIXTURE,
        REMOTE_LIBRARY_BUNDLE_FIXTURE,
        z2.ZSERVER_FIXTURE
    ),
    name='MaxttorTokenloginLayer:AcceptanceTesting'
)
