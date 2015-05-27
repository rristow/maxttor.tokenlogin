import logging
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from plone.session.plugins.session import SessionPlugin
from AccessControl import ClassSecurityInfo, AuthEncoding
from Products.PluggableAuthService.utils import classImplements
from Globals import InitializeClass
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin, ICredentialsUpdatePlugin
from Products.CMFCore.utils import getToolByName
from maxttor.tokenlogin.TokenLoginTool import tokenLoginTool
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from zope.publisher.browser import BrowserView
from zope.interface import implements
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
import binascii
import time
from email.Utils import formatdate

logger = logging.getLogger('mediQ.AuthenticateCredentials')

#manage_addTokenAuthenticator = PageTemplateFile('addTokenAuthenticator',
#    globals(), __name__='manage_addTokenAuthenticator')

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
#    meta_type = 'TokenAuthenticator'
#    security = ClassSecurityInfo()
    implements(IAuthenticationPlugin, IExtractionPlugin, ICredentialsUpdatePlugin)

    cookie_name = "__ac_token"
    cookie_lifetime = 10
    cookie_domain = '/'
    secure = False

    def __init__(self, id, title=None):
        self.__name__ = self.id = id
        self.title = title

    # ISessionPlugin implementation
    def _setupSession(self, response, token):
        self._setCookie(token, response)

    def _setCookie(self, cookie, response):
        secure = self.secure
        options = dict(path=self.path)
        #if self.cookie_domain:
        #    options['domain'] = self.cookie_domain
        if self.cookie_lifetime:
            options['expires'] = cookie_expiration_date(self.cookie_lifetime)
        print "set cookie ",self.cookie_name, " = ",cookie, " options: ", options
        response.setCookie(self.cookie_name, cookie, **options)

    def extractCredentials(self, request):
        authtoken=request.get("auth_token", None)
        if not authtoken:
            if self.cookie_name in request:
                authtoken = request.get(self.cookie_name)
                print "extractCredentials cookie ",self.cookie_name, " = ",authtoken
        else:
            print "extractCredentials request ",authtoken

        if authtoken:
            return {"source":"maxttor.tokenlogin", "token": authtoken}
        else:
            return {}

#TODO Activate
#    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials(self, credentials):
        ''' Authenticate credentials against the fake external database '''
        if not credentials.get("source", None)=="maxttor.tokenlogin":
            return None

        tokenstr = "[empty]"
        try:
            putils = getToolByName(self, 'plone_utils')

            #print "authenticateCredentials",self.REQUEST.form.keys()
            #import pdb;pdb.set_trace()

            #if 'auth_token' in self.REQUEST.form.keys():
            tokenstr = credentials.get('token', '')

            #if credentials.get() 'auth_token' in self.REQUEST.form.keys():
                #tokenstr = self.REQUEST.get('auth_token', '')
            if tokenstr:
                    token = tokenLoginTool.createTokenFromString(tokenstr)
                    if token:
                        if tokenLoginTool.checkToken(token):
                            #import pdb; pdb.set_trace()
                            print "TOKEN authenticateCredentials - OK"
                            self._setupSession(self.REQUEST.RESPONSE, token.toStr())
                            #site.acl_users.updateCredentials(site.REQUEST, site.REQUEST.RESPONSE, username, password)
                            # Authentication successful
                            return token.username, token.username

                        else:
                            print "TOKEN authenticateCredentials - error",tokenLoginTool.status_message
                            putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
                    else:
                        print "TOKEN authenticateCredentials - error",tokenLoginTool.status_message
                        putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
                    #else:
                    #print "TOKEN authenticateCredentials - error",tokenLoginTool.status_message
                    #putils.addPortalMessage(tokenLoginTool.status_message, type=u"error")
            else:
                #print "token login ignored"
                pass
        except Exception, detail:
            logger.error('token %s, exception: %s'%(tokenstr,detail))
            raise
#classImplements(TokenAuthenticator, IAuthenticationPlugin)
InitializeClass(TokenAuthenticator)
