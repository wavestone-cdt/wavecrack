#!/usr/bin/python
# coding: utf8
import ldap
import app_settings
import hashlib


def check_auth(username, password):
    """ Call the authentication function according to the authentication type defined in the settings """
    AUTH_TYPE = app_settings.AUTH_TYPE
    if AUTH_TYPE == "None":
        return check_auth_none(username, password)
    elif AUTH_TYPE == "Basic":
        return check_auth_basic(username, password)
    elif AUTH_TYPE == "LDAP":
        return check_auth_ldap(username, password)
    else:
        return False


def check_auth_none(username, password):
    """ Fake authenticator """
    return 'user@example.com'


def check_auth_basic(username, password):
    """ Basic authenticator """
    users = app_settings.BASIC_AUTH_USERS
    for user in users:
        if user[0] == username:
            hash = hashlib.sha256()
            hash.update(password)
            if user[1] == hash.hexdigest():
                return user[2]

    return False

# LDAP settings
LDAP_HOST = app_settings.LDAP_HOST
LDAP_TLS = app_settings.LDAP_TLS
LDAP_PORT = app_settings.LDAP_PORT
LDAP_NAME = app_settings.LDAP_NAME
LDAP_BASE_DN = app_settings.LDAP_BASE_DN
LDAP_SEARCH_FILTER = app_settings.LDAP_SEARCH_FILTER


def check_auth_ldap(username, password):
    """Login/password checking"""
    # Required options for LDAPS authentification
    user_email = ""
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    try:
        # LDAPS
        if LDAP_TLS:
            conn = ldap.initialize(
                "ldaps://" + LDAP_HOST + ":" + str(LDAP_PORT))
        else:
            conn = ldap.initialize(
                "ldap://" + LDAP_HOST + ":" + str(LDAP_PORT))
        conn.protocol_version = 3
        # Required for the operation
        conn.set_option(ldap.OPT_REFERRALS, 0)
        try:
            # LDAP injection prevention
            username = username.replace(",", "").replace("*", "").replace("|", "").replace("&", "").replace(
                "<", "").replace(">", "").replace("+", "").replace(";", "").replace("=", "").replace("\\", "")
            username = username.lower()
            # If login or password form field is empty, authentification
            # process is aborted
            if password == "" or username == "":
                return False
            else:
                # Properly logon
                result = conn.simple_bind_s(
                    username + "@" + LDAP_NAME, password)
                # Research parameters to find user's email
                basedn = LDAP_BASE_DN
                searchAttribute = ["mail"]
                searchFilter = LDAP_SEARCH_FILTER % username
                try:
                    result = conn.search_s(
                        basedn, ldap.SCOPE_SUBTREE, searchFilter, searchAttribute)
                    user_email = result[0][1]['mail'][0]
                    # Return email if research is successful
                    return user_email
                except Exception as e:
                    return user_email
                return user_email
        except ldap.INVALID_CREDENTIALS:
            return False
        except ldap.UNWILLING_TO_PERFORM:
            return False
        except ldap.LDAPError as e:
            return False
    except ldap.SERVER_DOWN:
        return False
    finally:
        # logout
        conn.unbind_s()
