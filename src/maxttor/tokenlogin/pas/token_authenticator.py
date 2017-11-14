import logging
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Globals import InitializeClass
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin, ICredentialsUpdatePlugin, ICredentialsResetPlugin
from Products.CMFCore.utils import getToolByName
from maxttor.tokenlogin.TokenLoginTool import tokenLoginTool
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from zope.publisher.browser import BrowserView
from zope.interface import implements
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
import time
from email.Utils import formatdate

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
        first_login=False

        # Extract token from request (login)
        authtoken=request.get("auth_token", None)
        if authtoken:
            first_login = True

        if not tool_active:
            if authtoken:
                # portal_message will have not effect here, because Plone will redirect to login.
                logging.warning("Token login is deactivated")
            self.resetCredentials(self.REQUEST, self.REQUEST.RESPONSE)
            return None

        # Check cookie (session active)
        if self.cookie_name in request:
            authtoken_cookie = request.get(self.cookie_name)
            if authtoken:
                if authtoken != authtoken_cookie:
                    # Renew the cookie
                    first_login = True
            else:
                authtoken = authtoken_cookie

        if authtoken:
            ret = {"source":"maxttor.tokenlogin", "token": authtoken, "first_login": first_login}
            return ret
        else:
            return {}

    def authenticateCredentials(self, credentials):
        putils = getToolByName(self, 'plone_utils')
        if not credentials.get("source", None) == "maxttor.tokenlogin":
            return None
        if not tokenLoginTool.isToolActive:
            logger.warning("Token login is deactivated")
            return None

        try:
            tokenstr = credentials.get('token', '')
            if tokenstr:
                token = tokenLoginTool.createTokenFromString(tokenstr)
                if tokenLoginTool.checkToken(self.REQUEST, token):
                    if credentials.get("first_login", False):
                        # make a session
                        self._setupSession(self.REQUEST.RESPONSE, tokenstr)
                        logger.warning("Token-login successful. User: '%s', token: '%s'"%(token.username, tokenstr))
                        return (token.username, token.username)
                else:
                    logger.warning("Token-login unsuccessful. Token: '%s'. %s"%(tokenstr, tokenLoginTool.status_message))
                    putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
        except Exception, detail:
            logger.error("Authenticate credentials error. Token: '%s', exception: %s"%(tokenstr,detail))
            raise

    def resetCredentials(self, request, response):
        response=self.REQUEST["RESPONSE"]
        if self.cookie_domain:
            response.expireCookie(
                self.cookie_name, path=self.path, domain=self.cookie_domain)
        else:
            response.expireCookie(self.cookie_name, path=self.path)

    def _setupSession(self, response, token):
        # save the token into the cookie
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
