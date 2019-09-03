# -*- coding: utf-8 -*-
# Copyright (c) 2017 idazco
# Copyright (c) 2019 nexiles GmbH
{
    'name': 'Auth0',
    'version': '2.0',
    'author': 'Nexiles GmbH',
    'summary': 'Auth0 module for Odoo',
    'website': 'https://github.com/nexiles/odoo_auth0',
    'description': 'Enables OAuth authentication through Auth0',
    'category': 'Authentication',
    'depends': [
        'auth_oauth', 'website'
    ],
    'data': [
        'data/data_auth0.xml',
        'data/auto_signup_data.xml',
        'views/signup.xml',
        'views/auth0_views.xml',
        'views/templates.xml',
        'views/res_config_settings_views.xml',
        'views/templates.xml',
        'security/ir.model.access.csv'
    ],
    'installable': True,
    'application': False,
    'auto_install': True,
}
