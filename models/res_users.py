# -*- coding: utf-8 -*-
# Copyright (c) 2017 idazco
# This file is heavily inspired by parts of Oddo, see COPYRIGHT for details
# Copyright (c) 2019 nexiles GmbH

import json
import logging

import requests
import jwt
from odoo import api, models
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    def _generate_oauth2_signup_values(self, provider, oauth_profile, token):
        email = oauth_profile['email']
        name = oauth_profile.get('name', email)
        return {
            'name': name,
            'login': email,
            'email': email,
            'oauth_provider_id': provider["id"],
            'oauth_access_token': token,
            'active': True,
        }

    @api.model
    def _auth_oauth2_signin(self, provider, oauth_profile, state, token):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param oauth_profile: the user profile provided by the oauth provider
            :param state: the state parameter as dictionary
            :param token: the token from the oauth provider
            :return: user login (str)
            :raise: AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        oauth_email = oauth_profile['email']
        try:
            user = self.search([("login", "=", oauth_email)])
            if not user:
                raise AccessDenied()
            assert len(user) == 1

            self.update_oauth2_user_info(user, provider, oauth_profile, token)

            return user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            # token = state.get('t')
            values = self._generate_oauth2_signup_values(provider, oauth_profile, token)
            values['partner_id'] = 0
            _logger.info("About to create new user %s" % values)
            try:
                _logger.info("Invitation scope %s" % self._get_signup_invitation_scope())
                _, login, _ = self.signup(values)
                _logger.info("Successfully created!")
                return login
            except SignupError as se:
                _logger.error("Traceback %s " % se)
                _logger.error("Signup Error for user with email %s using provider %s" % (oauth_email, provider["name"]))
                raise access_denied_exception

    @api.model
    def auth_oauth2(self, provider_id, code, state):
        provider = self.env['auth0.provider'].sudo().search_read([('id', '=', provider_id)])
        if not len(provider):
            _logger.error('No Providers, id: %s' % provider_id)
            return False
        provider = provider[0]

        token = self._auth_oauth2_token(provider, code)

        oauth_profile = self._auth_oauth2_profile(provider, token)

        # required check
        if not oauth_profile.get('email'):
            raise AccessDenied()

        # retrieve and sign in user
        login = self._auth_oauth2_signin(provider, oauth_profile, state, token)
        if not login:
            raise AccessDenied()
        # return user credentials

        return self.env.cr.dbname, login, token

    @api.model
    def _auth_oauth2_token(self, provider, code):
        """Returns the token from the OAuth2 Authentication server"""
        oauth_response = self._auth_oauth2_rpc(provider["validation_endpoint"], code, provider)
        if oauth_response.get('error'):
            raise Exception(oauth_response['error'])
        if "id_token" not in oauth_response:
            raise Exception("id_token not in response")
        return oauth_response['id_token']

    @api.model
    def _auth_oauth2_profile(self, provider, token):
        if provider["is_jwt"]:
            return self._parse_jwt(token, provider.get("jwt_secret"))
        # elif provider.data_endpoint:
        #     data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token, code, provider)
        #     validation.update(data)
        return {}

    @api.model
    def _auth_oauth2_rpc(self, url, code, provider):
        post_data = {
            'grant_type': 'authorization_code',
            'client_id': provider["client_id"],
            'client_secret': provider["client_secret"],
            'redirect_uri': '%s/auth0/callback' % (self.env['ir.config_parameter'].get_param('web.base.url')),
            'code': code,
        }
        resp = requests.post(url, json=post_data)
        self._check_rate_limits(resp)
        return resp.json()

    @staticmethod
    def _parse_jwt(token, jwt_secret=None):
        my_jwt = jwt.JWT()
        if not jwt_secret:
            data = my_jwt.decode(token, do_verify=False)
        else:
            data = my_jwt.decode(token, key=jwt_secret)
        return data

    def update_oauth2_user_info(self, user, provider, oauth_profile, token):
        email = oauth_profile['email']
        name = oauth_profile.get('name', email)
        user.sudo().write({
            'name': name,
            'login': email,
            'email': email,
            'oauth_provider_id': provider["id"],
            'oauth_access_token': token,
            'active': True,
        })

    @staticmethod
    def _check_rate_limits(validation_response):
        rate_limit_remaining = validation_response.headers.get('X-RateLimit-Remaining')
        if rate_limit_remaining.isdigit():
            rate_limit_remaining = int(rate_limit_remaining)
            if rate_limit_remaining < 2000:
                _logger.warn('Auth0 rate limit remaining: %d' % rate_limit_remaining)
            elif rate_limit_remaining < 500:
                _logger.warn('[critical] Auth0 rate limit remaining: %d' % rate_limit_remaining)
