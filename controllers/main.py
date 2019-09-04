# -*- coding: utf-8 -*-
# Copyright (c) 2017 idazco
# This file is heavily inspired by parts of Oddo, see COPYRIGHT for details
# Copyright (c) 2019 nexiles GmbH

import functools
import logging

import json

import werkzeug
import werkzeug.urls
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo import registry as registry_get

from odoo.addons.auth_oauth.controllers.main import OAuthLogin
from odoo.addons.web.controllers.main import set_cookie_and_redirect, login_and_redirect

_logger = logging.getLogger(__name__)


#----------------------------------------------------------
# helpers
#----------------------------------------------------------
def fragment_to_query_string(func):
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        return func(self, *a, **kw)
    return wrapper


class Auth0OAuthLogin(OAuthLogin):
    def list_providers(self):
        try:
            providers = request.env['auth0.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            providers = []

        for provider in providers:
            # request.session['auth0.session_db'] = request.session.db
            scope = provider['scope'] if 'email' in provider['scope'] else provider['scope'] + ' email'
            state = self.get_state(provider)
            state["r"] = "/web"
            params = dict(
                scope=scope,
                response_type='code',
                client_id=provider['client_id'],
                redirect_uri=request.httprequest.url_root + 'auth0/callback',
                state=json.dumps(state),
            )
            # link for the login button in login dialog
            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))

        return providers

    @http.route('/auth0/callback', type='http', auth='none', website=True)
    @fragment_to_query_string
    def callback(self, **kw):
        # todo: instead of showing an error, generate new session data and redirect to Auth0
        state = request.params.get('state')
        if not state:
            return 'No state provided'
        state = json.loads(state)

        provider_id = state['p']
        dbname = state['d']
        url = state['r']
        context = state.get('c', {})

        if not http.db_filter([dbname]):
            return BadRequest()

        if not request.params.get('code'):
            return 'Expected "code" param in URL, but its not there. Try again.'

        code = request.params.get('code')

        registry = registry_get(dbname)
        with registry.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, context)
            credentials = env['res.users'].sudo().auth_oauth2(provider_id, code, state)
            cr.commit()
            resp = login_and_redirect(*credentials, redirect_url=url)
            return resp

