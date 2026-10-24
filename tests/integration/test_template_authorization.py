import re
from unittest.mock import patch

import pytest

from powerdnsadmin.models.account import Account
from powerdnsadmin.models.account_user import AccountUser
from powerdnsadmin.models.base import db
from powerdnsadmin.models.domain import Domain
from powerdnsadmin.models.domain_template import DomainTemplate
from powerdnsadmin.models.domain_template_record import DomainTemplateRecord
from powerdnsadmin.models.history import History
from powerdnsadmin.models.record import Record
from powerdnsadmin.models.user import User


@pytest.fixture(scope='module')
def template_apply_users(app, initial_data):
    with app.app_context():
        operator = User(
            username='template-apply-operator',
            plain_text_password='OperatorPassword123!',
            email='template-apply-operator@example.com',
        )
        assert operator.create_local_user()['status']
        assert operator.set_role('Operator')['status']

        account = Account(name='template-apply-test-account')
        db.session.add(account)
        unrelated_account = Account(name='template-unrelated-test-account')
        db.session.add(unrelated_account)
        db.session.flush()
        ordinary_user = User.query.filter_by(
            username=app.config['TEST_USER']).one()
        db.session.add(AccountUser(account.id, ordinary_user.id))

        template = DomainTemplate(
            name='template-apply-security-test',
            description='Authorization test',
        )
        db.session.add(template)
        db.session.flush()
        template.records.append(DomainTemplateRecord(
            name='@',
            type='A',
            ttl=3600,
            data='192.0.2.1',
            comment='test',
            status=True,
        ))
        db.session.commit()

        user_ids = {
            'User': User.query.filter_by(
                username=app.config['TEST_USER']).one().id,
            'Operator': User.query.filter_by(
                username='template-apply-operator').one().id,
            'Administrator': User.query.filter_by(
                username=app.config['TEST_ADMIN_USER']).one().id,
        }
        account_id = account.id
        unrelated_account_id = unrelated_account.id
        template_id = template.id
    return {
        'user_ids': user_ids,
        'account_id': account_id,
        'unrelated_account_id': unrelated_account_id,
        'template_id': template_id,
    }


def authenticate(client, role_data, role):
    login_page = client.get('/login')
    csrf_token = re.search(
        rb'name="_csrf_token" value="([^"]+)"',
        login_page.data,
    ).group(1).decode()
    with client.session_transaction() as session:
        session['_user_id'] = str(role_data['user_ids'][role])
        session['_fresh'] = True
    return csrf_token


def template_apply_payload():
    return {
        'records': [{
            'record_name': '@',
            'record_type': 'A',
            'record_data': '192.0.2.1',
            'record_comment': '',
            'record_status': 'Active',
            'record_ttl': 3600,
        }]
    }


@pytest.mark.parametrize(
    ('role', 'expected_status'),
    [('User', 403), ('Operator', 200), ('Administrator', 200)],
)
def test_template_record_apply_requires_operator_role(
        app, client, template_apply_users, role, expected_status):
    csrf_token = authenticate(client, template_apply_users, role)
    with patch.object(
            DomainTemplate,
            'replace_records',
            return_value={'status': 'ok', 'msg': 'updated'},
    ) as replace_records:
        response = client.post(
            '/admin/template/template-apply-security-test/apply',
            json=template_apply_payload(),
            headers={'X-CSRFToken': csrf_token},
        )

    assert response.status_code == expected_status
    if role == 'User':
        replace_records.assert_not_called()
    else:
        replace_records.assert_called_once()


@pytest.mark.parametrize('role', ['User', 'Operator', 'Administrator'])
def test_template_pages_are_available_to_operator_and_admin(
        app, client, template_apply_users, role):
    authenticate(client, template_apply_users, role)
    expected_status = 403 if role == 'User' else 200

    assert client.get('/admin/templates').status_code == expected_status
    assert client.get('/admin/template/create').status_code == expected_status
    assert client.get(
        '/admin/template/template-apply-security-test/edit'
    ).status_code == expected_status


@pytest.mark.parametrize('role', ['User', 'Operator', 'Administrator'])
def test_template_create_requires_operator_role(
        app, client, template_apply_users, role):
    csrf_token = authenticate(client, template_apply_users, role)
    with patch.object(History, 'add'):
        response = client.post(
            '/admin/template/create',
            data={
                '_csrf_token': csrf_token,
                'name': 'created-by-' + role.lower(),
                'description': 'Role authorization test',
            },
        )

    assert response.status_code == (403 if role == 'User' else 302)


@pytest.mark.parametrize('role', ['User', 'Operator', 'Administrator'])
def test_create_template_from_zone_requires_operator_role(
        app, client, template_apply_users, role):
    csrf_token = authenticate(client, template_apply_users, role)
    with patch.object(History, 'add'):
        response = client.post(
            '/admin/template/create-from-zone',
            json={
                '_csrf_token': csrf_token,
                'name': 'from-zone-' + role.lower(),
                'description': 'Role authorization test',
                'domain': 'not-found.example',
            },
            headers={'X-CSRFToken': csrf_token},
        )

    assert response.status_code == (403 if role == 'User' else 200)


@pytest.mark.parametrize('role', ['User', 'Operator', 'Administrator'])
def test_template_delete_requires_operator_role(
        app, client, template_apply_users, role):
    csrf_token = authenticate(client, template_apply_users, role)
    template_name = 'delete-by-' + role.lower()
    with app.app_context():
        template = DomainTemplate(
            name=template_name, description='Role authorization test')
        assert template.create()['status'] == 'ok'

    response = client.post(
        '/admin/template/' + template_name + '/delete',
        data={'_csrf_token': csrf_token},
    )

    assert response.status_code == (403 if role == 'User' else 302)


@pytest.mark.parametrize('role', ['User', 'Operator', 'Administrator'])
def test_permitted_zone_creation_can_apply_template(
        app, client, template_apply_users, role):
    csrf_token = authenticate(client, template_apply_users, role)
    account_id = (
        str(template_apply_users['account_id'])
        if role == 'User' else '0'
    )
    form = client.get('/domain/add')
    assert form.status_code == 200

    with patch.object(
            Domain,
            'add',
            return_value={'status': 'ok', 'msg': 'zone created'},
    ), patch.object(Domain, 'get_id_by_name', return_value=None), patch.object(
            Domain, 'grant_privileges', return_value=True), patch.object(
            Record,
            'apply',
            return_value={
                'status': 'ok',
                'data': [{'rrsets': []}, {'rrsets': []}],
            },
    ) as apply_records, patch.object(History, 'add'):
        response = client.post(
            '/domain/add',
            data={
                '_csrf_token': csrf_token,
                'domain_name': 'template-use-' + role.lower() + '.example',
                'radio_type': 'native',
                'domain_template': str(template_apply_users['template_id']),
                'radio_type_soa_edit_api': 'DEFAULT',
                'accountid': account_id,
            },
        )

    assert response.status_code == 302
    apply_records.assert_called_once()
    assert apply_records.call_args.args[1][0]['record_data'] == '192.0.2.1'


@pytest.mark.parametrize('account_key', [None, 'unrelated_account_id'])
def test_user_cannot_create_zone_without_permitted_account(
        app, client, template_apply_users, account_key):
    csrf_token = authenticate(client, template_apply_users, 'User')
    account_id = (
        '0' if account_key is None
        else str(template_apply_users[account_key])
    )
    with patch.object(Domain, 'add') as add_domain:
        response = client.post(
            '/domain/add',
            data={
                '_csrf_token': csrf_token,
                'domain_name': 'template-use-unpermitted.example',
                'radio_type': 'native',
                'domain_template': str(template_apply_users['template_id']),
                'radio_type_soa_edit_api': 'DEFAULT',
                'accountid': account_id,
            },
        )

    assert response.status_code == 400
    add_domain.assert_not_called()


def test_user_cannot_create_zone_when_user_creation_is_disabled(
        app, client, template_apply_users):
    csrf_token = authenticate(client, template_apply_users, 'User')
    with patch('powerdnsadmin.decorators.Setting') as setting:
        setting.return_value.get.return_value = False
        response = client.post(
            '/domain/add',
            data={
                '_csrf_token': csrf_token,
                'domain_name': 'template-use-disabled.example',
                'radio_type': 'native',
                'domain_template': str(template_apply_users['template_id']),
                'radio_type_soa_edit_api': 'DEFAULT',
                'accountid': str(template_apply_users['account_id']),
            },
        )

    assert response.status_code == 403
