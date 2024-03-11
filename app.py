from datetime import datetime, timedelta

from wakatime import (
    auth,
    csrf,
)
from wakatime.compat import urlencode
from wakatime.models import (
    db,
    User,
    AuthClient,
    AuthClientCode,
    AuthClientGrant,
    AuthClientScope,
)
from wakatime.oauth import utils as oauth_utils

from flask import current_app as app
from flask import Blueprint, request, render_template, redirect, jsonify


blueprint = Blueprint('oauth_provider', __name__)


@blueprint.route('/authorize', methods=['GET', 'POST'])
@auth.login_required
def authorize():
    request.data  # must read request data before sending response (uWSGI+nginx flaw)

    choice = request.form.get('choice')

    # get url arguments
    response_type = request.args.get('response_type')
    client_id = request.args.get('client_id', request.args.get('app_id'))
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    scope = request.args.get('scope')
    force_approve = request.args.get('force_approve')

    errors = []
    client = None
    scopes = []

    supported_response_types = [
        'code',
        'token',
    ]

    # check url arguments
    if not client_id:
        errors.append('Missing client_id: This is required.')
    else:
        client = AuthClient.query.filter_by(public=client_id).first()
        if client is None or not client.is_active:
            errors.append('Invalid client_id: Not found.')
        else:
            if client.redirect_uris.filter_by(value=redirect_uri).first() is None:
                errors.append('Invalid redirect_uri: Not valid for this client.')
            if response_type not in supported_response_types:
                errors.append('Invalid response_type: Only response_types of {0} are supported.'.format(' or '.join(supported_response_types)))
            if not scope:
                errors.append('Missing scope: Must be comma-separated list of permissions.')
            else:
                try:
                    scope.split(',')
                except:
                    errors.append('Invalid scope: Must be comma-separated list of permissions.')
                if len(scope.split(',')) == 0:
                    errors.append('Invalid scope: Must request access to at least one permission.')
                else:
                    for scope in scope.split(','):
                        scope = scope.strip()
                        scope_obj = AuthClientScope.query.filter_by(value=scope).first()
                        if scope_obj is None or scope_obj.is_hidden:
                            errors.append(u'Invalid scope: {0}.'.format(scope))
                        else:
                            scopes.append(scope_obj)
            if state and len(state) >= 2000:
                errors.append('Invalid state: Maximum length is 2000 characters.')
            if force_approve is not None and force_approve not in ['true', 'false']:
                errors.append('Invalid force_approve: Must be either true or false (default is false).')

    if len(errors) == 0:

        previous_grant = oauth_utils.get_previous_grant_with_scopes(app.current_user, client, scopes) if not force_approve else None

        if request.method == 'POST' or previous_grant:

            # check if user clicked allow or deny
            choice = request.form.get('choice')

            if choice == 'allow' or previous_grant:

                if response_type == 'code':
                    code = AuthClientCode(
                        auth_client_id=client.id,
                        user_id=app.current_user.id,
                        value=oauth_utils.generate_token(type='sec'),
                        redirect_uri=redirect_uri,
                        state=state,
                        expires_at=datetime.utcnow() + timedelta(minutes=30),
                    )
                    db.session.add(code)
                    db.session.flush()
                    for s in previous_grant.scopes.all() if previous_grant else scopes:
                        code.scopes.append(s)
                    db.session.commit()

                    params = {
                        'code': code.value,
                    }
                    if state:
                        params['state'] = state
                    uri = oauth_utils.add_params_to_url(redirect_uri, params)
                    return redirect(uri)

                elif response_type == 'token':
                    grant = AuthClientGrant(
                        auth_client_id=client.id,
                        user_id=app.current_user.id,
                        access_token=oauth_utils.generate_token(type='sec'),
                        refresh_token=oauth_utils.generate_token(type='ref'),
                        expires_at=datetime.utcnow() + timedelta(hours=12),
                        is_implicit_grant=True,
                    )
                    db.session.add(grant)
                    db.session.flush()
                    for s in previous_grant.scopes.all() if previous_grant else scopes:
                        grant.scopes.append(s)
                    db.session.commit()

                    params = {
                        'access_token': grant.access_token,
                        'refresh_token': grant.refresh_token,
                        'uid': app.current_user.id,
                        'token_type': 'bearer',
                        'expires_in': grant.expires_in,
                        'scope': grant.scope,
                    }
                    if state:
                        params['state'] = state
                    uri = oauth_utils.add_params_to_url(redirect_uri, fragments=params)
                    return redirect(uri)

            elif choice == 'deny':
                params = {
                    'error': 'access_denied',
                    'error_description': 'The user has denied access.',
                }
                if state:
                    params['state'] = state

                if response_type == 'code':
                    uri = oauth_utils.add_params_to_url(redirect_uri, params=params)
                    return redirect(uri)
                elif response_type == 'token':
                    uri = oauth_utils.add_params_to_url(redirect_uri, fragments=params)
                    return redirect(uri)

            else:
                errors.append('Invalid choice: Must be allow or deny.')

    response_code = 200 if len(errors) == 0 else 400
    context = {
        'errors': errors,
        'response_code': response_code,
        'client': client,
        'scopes': scopes,
    }
    return render_template('oauth/provider/authorize.html', **context), response_code


@blueprint.route('/token', methods=['POST'])
@csrf.exempt
def token():
    request.data  # must read request data before sending response (uWSGI+nginx flaw)

    # get url arguments
    client_id = request.form.get('client_id', request.form.get('app_id'))
    client_secret = request.form.get('client_secret')
    grant_type = request.form.get('grant_type')

    # check url arguments
    if not client_id:
        return jsonify(error='invalid_client', error_description='client_id is required.'), 400
    else:
        client = AuthClient.query.filter_by(public=client_id).first()
        if client is None or not client.is_active:
            return jsonify(error='invalid_client', error_description='Client not found.'), 400
        else:
            if client.secret != client_secret:
                return jsonify(error='access_denied', error_description='client_secret is invalid.'), 401

            if grant_type == 'authorization_code':
                code = client.auth_codes.filter_by(value=request.form.get('code')).first()
                if code is None or code.is_invalid or code.used_at is not None:
                    return jsonify(error='invalid_request', error_description='code is invalid.'), 400
                if code.expires_at <= datetime.utcnow():
                    return jsonify(error='invalid_request', error_description='code has expired.'), 400
                redirect_uri = request.form.get('redirect_uri')
                if redirect_uri != code.redirect_uri:
                    return jsonify(error='invalid_request', error_description='redirect_uri does not match the one used for this code.'), 400
                if client.redirect_uris.filter_by(value=redirect_uri).first() is None:
                    return jsonify(error='invalid_request', error_description='redirect_uri is invalid.'), 400

                user = User.query.filter_by(id=code.user_id, active=True).first()
                if user is None:
                    return jsonify(error='invalid_request', error_description='User is no longer valid.'), 400

                grant = AuthClientGrant(
                    auth_client_id=client.id,
                    user_id=user.id,
                    access_token=oauth_utils.generate_token(type='sec'),
                    refresh_token=oauth_utils.generate_token(type='ref'),
                    expires_at=datetime.utcnow() + timedelta(days=60),
                )
                db.session.add(grant)
                code.is_invalid = True
                code.used_at = datetime.utcnow()
                db.session.flush()
                for s in code.scopes:
                    grant.scopes.append(s)
                db.session.commit()

                data = {
                    'access_token': grant.access_token,
                    'refresh_token': grant.refresh_token,
                    'uid': user.id,
                    'token_type': 'bearer',
                    'expires_in': grant.expires_in,
                    'scope': grant.scope,
                }
                if request.headers.get('Accept') == 'application/x-www-form-urlencoded':
                    return urlencode(data)
                else:
                    return jsonify(**data)

            elif grant_type == 'refresh_token':
                refresh_token = client.access_tokens.filter_by(refresh_token=request.form.get('refresh_token')).first()
                if refresh_token is None or refresh_token.is_invalid:
                    return jsonify(error='invalid_request', error_description='refresh_token is invalid.'), 400

                user = User.query.filter_by(id=refresh_token.user_id, active=True).first()
                if user is None:
                    return jsonify(error='invalid_request', error_description='User is no longer valid.'), 400

                grant = AuthClientGrant(
                    auth_client_id=client.id,
                    user_id=user.id,
                    access_token=oauth_utils.generate_token(type='sec'),
                    refresh_token=oauth_utils.generate_token(type='ref'),
                    expires_at=datetime.utcnow() + timedelta(days=60),
                )
                db.session.add(grant)
                refresh_token.is_invalid = True
                db.session.flush()
                for s in refresh_token.scopes:
                    grant.scopes.append(s)
                db.session.commit()

                data = {
                    'access_token': grant.access_token,
                    'refresh_token': grant.refresh_token,
                    'uid': user.id,
                    'token_type': 'bearer',
                    'expires_in': grant.expires_in,
                    'scope': grant.scope,
                }
                if request.headers.get('Accept') == 'application/x-www-form-urlencoded':
                    return urlencode(data)
                else:
                    return jsonify(**data)

            else:
                return jsonify(error='unsupported_grant_type', error_description='Only grant_type of authorization_code or refresh_token supported.'), 400

    raise Exception('Execution should never reach here.')


@blueprint.route('/disable_access_token', methods=['POST'])
@auth.login_required
def disable_access_token():
    request.data  # must read request data before sending response (uWSGI+nginx flaw)
    raise Exception('Not yet implemented.')
