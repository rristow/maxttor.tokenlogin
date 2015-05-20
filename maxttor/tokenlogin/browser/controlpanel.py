from plone.app.registry.browser import controlpanel
from maxttor.tokenlogin.interfaces import ITokenLoginSettings
from maxttor.tokenlogin import _

class TokenLoginSettingsEditForm(controlpanel.RegistryEditForm):
    schema = ITokenLoginSettings
    label = _(u"Token Login Settings")
    description = _(u"Token login authentication settings.")

    def updateFields(self):
        super(TokenLoginSettingsEditForm, self).updateFields()

    def updateWidgets(self):
        super(TokenLoginSettingsEditForm, self).updateWidgets()

class TokenLoginSettingsEditFormControlPanel(controlpanel.ControlPanelFormWrapper):
    form = TokenLoginSettingsEditForm
