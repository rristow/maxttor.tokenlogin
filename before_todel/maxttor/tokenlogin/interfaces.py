#-*- coding: utf-8 -*-
from z3c.form import interfaces

from zope import schema
from zope.interface import Interface
from zope.i18nmessageid import MessageFactory

_ = MessageFactory('maxttor.tokenlogin')

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

# TODO: implement Fractional
#    token_duration = schema.Float(
#            title=_(u"token duration"),
#            description=_(u"The number of days that the token will be active or '0' if the token never expires."
#                          u"(Fractional days are allowed, e.g. 0.042 is approx. 1h, 0.01 is approx. 15min)"),
#            required=True,
#            default=0)

class ITokenLogin(Interface):
    """Marker interface
    """