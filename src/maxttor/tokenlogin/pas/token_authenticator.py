import logging
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from plone.session.plugins.session import SessionPlugin
from AccessControl import ClassSecurityInfo, AuthEncoding
from Products.PluggableAuthService.utils import classImplements
from Globals import InitializeClass
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin, ICredentialsUpdatePlugin, ICredentialsResetPlugin
from Products.CMFCore.utils import getToolByName
from maxttor.tokenlogin.TokenLoginTool import tokenLoginTool
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from zope.publisher.browser import BrowserView
from zope.interface import implements
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
import binascii
import time
from email.Utils import formatdate
from maxttor.tokenlogin import _

logger = logging.getLogger('maxttor.tokenlogin')

def cookie_expiration_date(days):
    expires = time.time() + (days * 24 * 60 * 60)
    return formatdate(expires, usegmt=True)

class AddForm(BrowserView):
    """Add form the PAS plugin
    """

    _template = ViewPageTemplateFile('addTokenAuthenticator.zpt')

    def __call__(self):
        if 'form.button.Add' in self.request.form:
            name = self.request.form.get('id')
            title = self.request.form.get('title')
            plugin = TokenAuthenticator(name, title)
            self.context.context[name] = plugin
            self.request.response.redirect(
              self.context.absolute_url() +
              '/manage_workspace?manage_tabs_message=Plugin+added.')
        else:
            return self._template(self.request)

class TokenAuthenticator(BasePlugin):
    ''' Plugin for Token Authentication '''

    implements(IAuthenticationPlugin, IExtractionPlugin, ICredentialsUpdatePlugin, ICredentialsResetPlugin)

    cookie_name = "__ac_token"
    cookie_lifetime = 10
    cookie_domain = ''
    secure = False
    path = "/"

    def __init__(self, id, title=None):
        self.__name__ = self.id = id
        self.title = title

    def extractCredentials(self, request):
        putils = getToolByName(self, 'plone_utils')
        tool_active = tokenLoginTool.isToolActive

        # Extract token from request
        authtoken=request.get("auth_token", None)

        if not authtoken:
            if self.cookie_name in request:
                if tool_active:
                    # Extract token from cookie
                    authtoken = request.get(self.cookie_name)
                else:
                    # logout - tool deactivated
                    self.resetCredentials(self.REQUEST, self.REQUEST.RESPONSE)
        else:
            # save the token into the cookie
            if tool_active:
                self._setupSession(self.REQUEST.RESPONSE, authtoken)
            else:
                putils.addPortalMessage(_("Token login is deactivated"), type=u"error")
                return None

        if authtoken:
            return {"source":"maxttor.tokenlogin", "token": authtoken}
        else:
            return {}

    def authenticateCredentials(self, credentials):
        putils = getToolByName(self, 'plone_utils')
        if not credentials.get("source", None)=="maxttor.tokenlogin":
            return None
        if not tokenLoginTool.isToolActive:
            putils.addPortalMessage(_("Token login is deactivated"), type=u"error")
            return None

        tokenstr = "[empty]"
        try:
            tokenstr = credentials.get('token', '')

            if tokenstr:
                token = tokenLoginTool.createTokenFromString(tokenstr)
                if token:
                    if tokenLoginTool.checkToken(token):
                        return (token.username, token.username)
                    else:
                        putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
                else:
                    putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
        except Exception, detail:
            logger.error('token %s, exception: %s'%(tokenstr,detail))
            raise

    def resetCredentials(self, request, response):
        response=self.REQUEST["RESPONSE"]
        if self.cookie_domain:
            response.expireCookie(
                self.cookie_name, path=self.path, domain=self.cookie_domain)
        else:
            response.expireCookie(self.cookie_name, path=self.path)

    def _setupSession(self, response, token):
        self._setCookie(token, response)

    def _setCookie(self, cookie, response):
        secure = self.secure
        options = dict(path=self.path, secure=self.secure, http_only=True)
        if self.cookie_domain:
            options['domain'] = self.cookie_domain
        if self.cookie_lifetime:
            options['expires'] = cookie_expiration_date(self.cookie_lifetime)
        response.setCookie(self.cookie_name, cookie, **options)

InitializeClass(TokenAuthenticator)
