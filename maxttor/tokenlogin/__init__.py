from zope.i18nmessageid import MessageFactory
from maxttor.tokenlogin.pas import token_authenticator
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin

_ = MessageFactory('maxttor.tokenlogin')

def initialize_TODEL(context):
    #TODO:rr
    import pdb; pdb.set_trace()

    registerMultiPlugin(token_authenticator.TokenAuthenticator.meta_type) # Add to PAS menu
    context.registerClass(token_authenticator.TokenAuthenticator,
                          constructors = (token_authenticator.manage_addTokenAuthenticator,
                                          token_authenticator.addTokenAuthenticator),
                          visibility = None)

