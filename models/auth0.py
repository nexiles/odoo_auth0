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
    is_jwt = fields.Boolean(string='Token Format is JWT')
    jwt_secret = fields.Char(string='JWT Secret')
