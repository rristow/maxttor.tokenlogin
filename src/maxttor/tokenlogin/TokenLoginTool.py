# -*- coding: utf-8 -*-
from cmath import atan
from lib2to3.btm_utils import tokens
import uuid
from ZODB.POSException import ConflictError
from Products.CMFCore.utils import getToolByName
from zope.component import getUtility
from Acquisition import aq_inner
from datetime import datetime, timedelta, date
from plone.registry.interfaces import IRegistry
from maxttor.tokenlogin.interfaces import ITokenLoginSettings
from zope.component.hooks import getSite
from Products.PASIPAuth.cidr import in_cidr
from Products.PASIPAuth.cidr import cidr

try:
    from zope.component.hooks import getSite
except ImportError:
    from zope.app.component.hooks import getSite
import logging

logger = logging.getLogger('maxttor.tokenlogin')
TOKEN_SIZE = 8


def iprange_str_to_list(ipstr):
    """ Convert an string with multiple CIDR IP addresses into a list. Check if the CDIR is valid.

    :param self:
    :param ipstr:
    :return:
    """
    res = []
    if ipstr:
        for ip in ipstr.replace(",", " ").replace(";", " ").split(" "):
            if ip:
                ip_component = ip.split("/")
                # prefix
                cidr(ip_component[0])
                if len(ip_component) == 2:
                    int(ip_component[1])
                elif len(ip_component) > 2:
                    raise ValueError("Wrong CIDR format")
                res.append(ip)
    return res


class Token(object):
    username = None
    token_key = None
    token_creation = None
    allowediprange = None

    def __init__(self, username, token_key=None, token_creation=None, allowediprange=None):
        if not username:
            raise Exception("Invalid username")
        self.username = username
        if not token_key:
            token_key = self._generateKey()
        self.token_key = token_key
        if not token_creation:
            token_creation = datetime.now()
        self.allowediprange = iprange_str_to_list(allowediprange)
        self.token_creation = token_creation

    def showInfo(self):
        return "token: %s (username: %s, token_key: %s, token_creation: %s)"%(self.toStr(), self.username, self.token_key, self.token_creation)

    def toStr(self):
        """
        The token as a String.
        :return:
        """
        """
        :return:
        """
        return self.__str__()

    def _getConfig(self):
        """
        Get the configuration for the tokenlogin product.
        """
        ru = getUtility(IRegistry)
        return ru.forInterface(ITokenLoginSettings)

    def isExpired(self):
        """ Verify is the token is expired """
        days = self._getConfig().token_duration
        if days:
            now = datetime.now()
            valid_until =  self.token_creation + timedelta(days=days)
            return now > valid_until
        else:
            return False

    def __str__(self):
        tokenstr = "%s%s"%(self.token_key,self.username)
        return tokenstr.encode("base64")

    def _generateKey(self):
        """
        Return a key for the token.
        :return: key as String
        """
        site = getSite()
        portal_registration = getToolByName(site, 'portal_registration')
        return portal_registration.generatePassword()[:TOKEN_SIZE]

    def rewriteTokenKey(self):
        """
        Rewrite the internal key creating a new token for this user.
        :return: token-string
        """
        self.token_key = self._generateKey()
        self.token_creation = datetime.now()
        return self.toStr()

class TokenLoginTool(object):
    """ Control the status (active, inactive, offline) of the user's sessions """

    def __init__(self):
        self.staus_message = ""

    def _getConfig(self):
        """
        Get the configuration for the tokenlogin product.
        """
        ru = getUtility(IRegistry)
        return ru.forInterface(ITokenLoginSettings)

    @property
    def isToolActive(self):
        """ Return if the Product is active  """
        return self._getConfig().enabled

    def getToken(self, username=None):
        """
        Return the token from this user
        :param username: the username id
        :return: One Token object or None if no token available. (status_message will be updated)
        """
        self.status_message = ""
        site = getSite()
        membership = getToolByName(site, 'portal_membership')
        if username:
            member = membership.getMemberById(username)
        else:
            member = membership.getAuthenticatedMember()
        if member:
            username = member.id
            auth_token = member.getProperty('auth_token',None)
            auth_token_creation = member.getProperty('auth_token_creation', None)
            allowediprange = member.getProperty('auth_token_allowediprange', None)
            if auth_token:
                return self._createTokenFromString(auth_token, auth_token_creation, allowediprange)
            else:
                return None
        else:
            self.status_message = "member not found"
            return None

    def saveToken(self, token, allowediprange=None):
        """
        Save the token for this user.
        :param username: the username id.
        :param tokenstr: the token string (use the generateToken function)
        :return: True if saved or False if there is an error
        """
        site = getSite()
        putils = getToolByName(site, 'plone_utils')
        membership = getToolByName(site, 'portal_membership')

        #username = self.extractUserName(tokenstr)
        member = membership.getMemberById(token.username)
        if member:
            data = {"auth_token":token.toStr(), "auth_token_creation":datetime.now()}
            if allowediprange:
                data['auth_token_allowediprange'] = allowediprange

            member.setMemberProperties(data)
            return True
        else:
            return False

    def deleteToken(self, username=None):
        """
        Delete the token for this user.
        :param username: the username id.
        :param tokenstr: the token string (use the generateToken function)
        :return: True if saved or False if there is an error
        """
        self.status_message = ""
        site = getSite()
        membership = getToolByName(site, 'portal_membership')
        if username:
            member = membership.getMemberById(username)
        else:
            member = membership.getAuthenticatedMember()

        if member:
            member.setProperties(auth_token="", auth_token_creation=0)
            return True
        else:
            return False

    def _createTokenFromString(self, tokenstr, token_creation=None, allowediprange=None):
        """
        Create a new token from String. (Do not load the token-date)
        :param token: the token string.
        :return: The token object.
        """
        self.status_message = ""
        try:
            token_dec = tokenstr.decode("base64")
            token_key = token_dec[:TOKEN_SIZE]
            token_user = token_dec[TOKEN_SIZE:]
            return Token(token_user, token_key, token_creation, allowediprange)
        except (ConflictError, KeyboardInterrupt):
            raise
        except Exception, detail:
            self.status_message = "Error decoding token. %s"%detail
            return None

    def createTokenFromString(self, tokenstr):
        """
        Create a new token from String. Load also the creation date if token is valid.
        :param token: the token string.
        :return: The token object.
        """
        self.status_message = ""
        token_new = self._createTokenFromString(tokenstr)
        if token_new:
            username = token_new.username
            token_user = self.getToken(username)

            if token_user and token_user.toStr() == token_new.toStr():
                return token_user
            else:
                return token_new

    def createToken(self, token_user=None, token_key=None):
        """
        Create a new token for the user.
        :param token_user: username
        :param token_key: the key
        :return: Token object
        """
        if not token_user:
            site = getSite()
            membership = getToolByName(site, 'portal_membership')
            member = membership.getAuthenticatedMember()
            token_user = member.id
        return Token(token_user, token_key)

    def check_cidr(self, member_ip, allowediprange):
        if allowediprange:
            for iprange in allowediprange:
                iprange = iprange.strip()
                if in_cidr(member_ip, iprange):
                    return True
            return False
        else:
            return True

    def check_ip_range(self, request, ip_range_list):
        # get all valid IP address from client (with gateways)
        forwarded_ips = []
        for ip_address in request.get('HTTP_X_FORWARDED_FOR', '').split(','):
            ip_address = ip_address.strip()
            if ip_address:
                forwarded_ips.append(ip_address)

        # Verify all ip ranges
        for ip_range in ip_range_list:
            clientAddr = request.getClientAddr()
            if in_cidr(clientAddr, ip_range):
                return clientAddr
            for clientAddr_fwd in forwarded_ips:
                if in_cidr(clientAddr_fwd, ip_range):
                    return clientAddr_fwd

    def checkToken(self, request, token):
        """
        Verify if the token is valid
        :param token: token object
        :return: (status_message will be updated)
        """
        self.status_message = ""
        if token:
            member_token = self.getToken(token.username)

            if member_token:
                if member_token.toStr() == token.toStr():
                    if not member_token.isExpired():
                        if member_token.allowediprange:
                            user_ip = member_token.allowediprange
                            if self.check_ip_range(request, user_ip):
                                return True
                            else:
                                self.status_message = "The IP '%s' is not allowed." % user_ip
                                return False
                        else:
                            return True
                    else:
                        self.status_message = "The token is expired. Please request a new one"
                        return False
                else:
                    self.status_message = "The token is invalid (not found)"
                    return False
            else:
                self.status_message = "The token is invalid (invalid member)"
                return False
        else:
            self.status_message = "The token is invalid (None)"
            return False

tokenLoginTool = TokenLoginTool()
