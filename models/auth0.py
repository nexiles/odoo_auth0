# -*- coding: utf-8 -*-
# Copyright (c) 2017 idazco
# Copyright (c) 2019 nexiles GmbH

from odoo import fields, models
import requests

from odoo.exceptions import UserError
import json


class Auth0(models.Model):
    _inherit = 'auth.oauth.provider'
    _name = 'auth0.provider'
    _description = 'Extendend OAuth2 Model to support the code flow'

    client_secret = fields.Char(string='Client Secret')
    jwt_secret = fields.Char(string='JWT Secret')

    def get_auth0_oauth_provider(self):
        return self.env['auth0.provider'].sudo().search([
            ('id', '=', self.env.ref('auth_oauth_provider_auth0').id),
        ], limit=1)

    def create_auth0_oauth_client(self, access_token, uuid, subdomain_name):
        url = self.env['ir.config_parameter'].get_param('auth0_oauth.url_api_users_clients')
        params = {
            'userID': uuid,
            'name': subdomain_name,
            'redirect': 'https://%s/auth_oauth/signin' % subdomain_name,
        }
        headers = {'Authorization': 'Bearer %s' % access_token}

        f = requests.post(url=url, params=params, headers=headers)
        response = f.content
        response = json.loads(response)

        if response.get('error'):
            raise UserError('Could not create the client: %s' % response)

        return response
