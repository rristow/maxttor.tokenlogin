from Acquisition import aq_inner
from zope.interface import implements
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from plone.app.layout.viewlets import ViewletBase
from Products.Five.browser import BrowserView
from zope.component import getUtility
from plone.registry.interfaces import IRegistry
from zope.viewlet.interfaces import IViewlet
from maxttor.tokenlogin.TokenLoginTool import tokenLoginTool
from Products.CMFCore.utils import getToolByName
from Products.statusmessages.interfaces import IStatusMessage
from z3c.form import form, field, button
from Products.CMFCore.interfaces import ISiteRoot
from Products.statusmessages.interfaces import IStatusMessage
from zope.interface import Interface
from zope import schema
from datetime import datetime
from zope.security import checkPermission
from AccessControl import getSecurityManager
from AccessControl import Unauthorized
from Products.CMFCore import permissions
from maxttor.tokenlogin.TokenLoginTool import iprange_str_to_list

try:
    from zope.component.hooks import getSite
except ImportError:
    from zope.app.component.hooks import getSite
from maxttor.tokenlogin import _


class ManageTokenView(BrowserView):
    """ Manage the tokens  """
    template = ViewPageTemplateFile('manage-token.pt')

    def normalize_iprange(self, ipstr):
        return "; ".join(iprange_str_to_list(ipstr))

    def check_ip_range(self, ipstr):
        try:
            iprange_str_to_list(ipstr)
            return True
        except ValueError:
            return False

    def __call__(self):
        context = aq_inner(self.context)
        request = context.REQUEST

        site = getSite()

        membership = getToolByName(site, 'portal_membership')
        putils = getToolByName(self, 'plone_utils')
        member = member = membership.getAuthenticatedMember()
        userid_actual=""
        if member:
            userid_actual = member.id
        self.userid = self.request.get('user', None)

        if not self.userid:
            self.userid = userid_actual

        if self.userid != userid_actual and not self.isManager:
            raise Unauthorized("you need administration rights")

        self.token = tokenLoginTool.getToken(self.userid)

        if self.request.get('action_generate', None):
            self.allowediprange = self.request.get('allowediprange', None)
            if self.allowediprange and self.check_ip_range(self.allowediprange):
                if self.token:
                    self.token.rewriteTokenKey()
                else:
                    self.allowediprange = self.normalize_iprange(self.allowediprange)
                    self.token = tokenLoginTool.createToken(self.userid, self.allowediprange)
            else:
                putils.addPortalMessage(_(u"It was not possible to save the token. The IP Range is not valid.") +
                                        str(tokenLoginTool.status_message), type=u"error")
        elif self.request.get('action_save', None):
            self.allowediprange = self.request.get('allowediprange', None)
            if self.allowediprange and self.check_ip_range(self.allowediprange):
                self.allowediprange = self.normalize_iprange(self.allowediprange)
                if tokenLoginTool.saveToken(self.token, allowediprange=self.allowediprange):
                    self.token = tokenLoginTool.getToken(self.userid)
                    putils.addPortalMessage(_(u"The token was saved."), type=u"warning")
                else:
                    putils.addPortalMessage(_(u"It was not possible to save the token.")+str(tokenLoginTool.status_message), type=u"error")
            else:
                putils.addPortalMessage(_(u"It was not possible to save the token. The IP Range is not valid.") +
                                        str(tokenLoginTool.status_message), type=u"error")
        elif self.request.get('action_delete', None):
            if tokenLoginTool.deleteToken(self.userid):
                self.token = None
                putils.addPortalMessage(_(u"The token was deleted."), type=u"warning")
            else:
                putils.addPortalMessage(_(u"It was not possible to delete the token.")+str(tokenLoginTool.status_message), type=u"warning")

        return self.template()

    @property
    def isManager(self):
        return getSecurityManager().checkPermission(permissions.ManagePortal, self.context)

    @property
    def get_token_data(self):
        if self.token:
            ret = {'userid': self.userid,
                    'creation': self.token.token_creation.strftime("%d.%m.%Y %H:%M"),
                    'token_str': self.token.toStr(),
                    'allowediprange': str(self.token.allowediprange) and "; ".join(self.token.allowediprange) or ""
                   }
            return ret
        else:
            return None
