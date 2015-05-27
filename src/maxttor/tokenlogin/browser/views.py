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
try:
    from zope.component.hooks import getSite
except ImportError:
    from zope.app.component.hooks import getSite
from maxttor.tokenlogin import _

class ManageTokenView2(BrowserView):
    """ Manage the tokens  """
    template = ViewPageTemplateFile('manage-token.pt')

    def __call__(self):
        context = aq_inner(self.context)        
        request = context.REQUEST
        putils = getToolByName(self, 'plone_utils')
        #request.set('disable_border', True)

        self.token = tokenLoginTool.getToken()
        action = request.get('action')
        if action == "generate_token":
            if self.token:
                self.token.rewriteTokenKey()
            else:
                self.token = tokenLoginTool.createToken()
        elif action == "save_token":
            if tokenLoginTool.saveTokenData(self.token):
                putils.addPortalMessage(u"The token was saved.", type=u"warning")
            else:
                putils.addPortalMessage(u"It was not possible to save the token. %s"%tokenLoginTool.status_message, type=u"error")
        return self.template()

class IManageTokenView(Interface):
    """ Define form fields """

    token = schema.Text(
            title=_(u"Token"),
            description=_(u"The registered token"),
            required=False,
            readonly=True,
            default=u"")

    token_creation = schema.Text(
            title=_(u"creation date"),
            required=False,
            readonly=True,
            default=u"")

class ManageTokenView(form.Form):
    fields = field.Fields(IManageTokenView)
    ignoreContext = True

    def _load_widgets(self):
        if self.token:
            #TODO : Remove
            print self.token.showInfo()
            self.widgets['token'].value = self.token.toStr()
            if self.token.token_creation:
                print self.token.token_creation
                self.widgets['token_creation'].value = self.token.token_creation.strftime("%d.%m.%Y %H:%M")
        print "_load_widgets",  self.token.showInfo()

    def updateWidgets(self):
        super(ManageTokenView, self).updateWidgets()
        tokenstr = self.request.get('token', None)
        print "updateWidgets"
        if tokenstr:
            self.token = tokenLoginTool.createTokenFromString(tokenstr)
            print "createTokenFromString",tokenstr
        else:
            self.token = tokenLoginTool.getToken()
            print "get Token from user",self.token.showInfo()
        self._load_widgets()

    def update(self):
        # disable Plone's editable border
        self.request.set('disable_border', True)
        super(ManageTokenView, self).update()

    @button.buttonAndHandler(_(u'Generate new token'))
    def handleGenerate(self, action):
        if self.token and self.token.username:
            self.token.rewriteTokenKey()
        else:
            self.token = tokenLoginTool.createToken()
        print "generate new token",  self.token.showInfo()
        res = tokenLoginTool.saveToken(self.token)
        self._load_widgets()
        if res:
            self.status = _(u"The token was saved.")
        else:
            self.status = _(u"It was not possible to save the token. %s")%tokenLoginTool.status_message

class TokenLoginView(BrowserView):
    """ Manage the tokens  """

    template = ViewPageTemplateFile('tokenlogin.pt')
    def __call__(self):
        site = getSite()
        context = aq_inner(self.context)
        request = context.REQUEST
        putils = getToolByName(self, 'plone_utils')

        self.token = tokenLoginTool.getToken()
        auth_token = request.get('auth_token')
        if auth_token:
            site.acl_users.updateCredentials(site.REQUEST, site.REQUEST.RESPONSE, username, password)

        return self.template()

