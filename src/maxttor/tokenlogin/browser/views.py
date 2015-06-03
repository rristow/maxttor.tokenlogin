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

try:
    from zope.component.hooks import getSite
except ImportError:
    from zope.app.component.hooks import getSite
from maxttor.tokenlogin import _


class ManageTokenView(BrowserView):
    """ Manage the tokens  """
    template = ViewPageTemplateFile('manage-token.pt')

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
            if self.token:
                self.token.rewriteTokenKey()
            else:
                self.token = tokenLoginTool.createToken(self.userid)
            if tokenLoginTool.saveToken(self.token):
                putils.addPortalMessage(_(u"The token was saved."), type=u"warning")
            else:
                putils.addPortalMessage(_(u"It was not possible to save the token.")+str(tokenLoginTool.status_message), type=u"error")

        if self.request.get('action_delete', None):
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
            return {'userid': self.userid,
                    'creation': self.token.token_creation.strftime("%d.%m.%Y %H:%M"),
                    'token_str': self.token.toStr()}
        else:
            return None
