from Products.CMFCore.utils import getToolByName
from Products.PlonePAS.Extensions.Install import \
    activatePluginInterfaces
from maxttor.tokenlogin.pas.token_authenticator import TokenAuthenticator
from StringIO import StringIO

def setupVarious(context):
    # Ordinarily, GenericSetup handlers check for the existence of XML files.
    # Here, we are not parsing an XML file, but we use this text file as a
    # flag to check that we actually meant for this import step to be run.
    # The file is found in profiles/default.
    if context.readDataFile('maxttor.tokenlogin_various.txt') is None:
        return
    site = context.getSite()
    out = StringIO()
    installPASPlugin(site)

def installPASPlugin(portal, name='tokenlogin'):
    out = StringIO()
    userFolder = portal['acl_users']
    if name not in userFolder:

        plugin = TokenAuthenticator(name, 'tokenlogin authenticator')
        userFolder[name] = plugin
        activatePluginInterfaces(portal, name, out)
        print >> out, 'tokenlogin authenticator added'
        plugins = userFolder['plugins']
        for info in plugins.listPluginTypeInfo():
            interface = info['interface']
            if plugin.testImplements(interface):
                active = list(plugins.listPluginIds(interface))
                if name in active:
                    active.remove(name)
                    active.insert(0, name)
                    plugins._plugins[interface] = tuple(active)
        return out.getvalue()




