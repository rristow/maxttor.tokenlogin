# -*- coding: utf-8 -*-
"""Module where all interfaces, events and exceptions live."""

from zope.i18nmessageid import MessageFactory
from maxttor.tokenlogin import _
from zope import schema
from zope.interface import Interface
from zope.publisher.interfaces.browser import IDefaultBrowserLayer

_ = MessageFactory('maxttor.tokenlogin')

class IMaxttorTokenloginLayer(IDefaultBrowserLayer):
    """Marker interface that defines a browser layer."""

class ITokenLoginSettings(Interface):
    """ Global tokenplugin settings. This describes records stored in the
    configuration registry and obtainable via plone.registry.
    """

    enabled = schema.Bool(
            title=_(u"Enabled"),
            description=_(u"Enabled the token login"),
            required=True,
            default=True,
        )

    token_duration = schema.Int(
            title=_(u"token duration"),
            description=_(u"The number of days that the token will be active or '0' if the token never expires."),
            required=True,
            default=0)

class ITokenLogin(Interface):
    """Marker interface
    """