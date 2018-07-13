from __future__ import absolute_import

import pytest

import rbac.acl
import rbac.proxy


@pytest.fixture(params=[
    lambda: rbac.acl.Registry(),
    lambda: rbac.proxy.RegistryProxy(rbac.acl.Registry()),
], ids=['registry', 'registry_proxy'])
def acl(request):
    # create acl registry from parametrized factory
    acl = request.param()

    # add roles
    acl.add_role('user')
    acl.add_role('actived_user', parents=['user'])
    acl.add_role('writer', parents=['actived_user'])
    acl.add_role('manager', parents=['actived_user'])
    acl.add_role('editor', parents=['writer', 'manager'])
    acl.add_role('super')

    # add resources
    acl.add_resource('comment')
    acl.add_resource('post')
    acl.add_resource('news', parents=['post'])
    acl.add_resource('infor', parents=['post'])
    acl.add_resource('event', parents=['news'])

    # set super permission
    acl.allow('super', None, None)

    return acl


def test_allow(acl):
    # add allowed rules
    acl.allow('actived_user', 'view', 'news')
    acl.allow('writer', 'new', 'news')

    # test 'view' operation
    roles = ['actived_user', 'writer', 'manager', 'editor']

    for role in roles:
        for resource in ['news', 'event']:
            assert acl.is_allowed(role, 'view', resource)
        for resource in ['post', 'infor']:
            assert not acl.is_allowed(role, 'view', resource)

    for resource in ['news', 'event']:
        assert acl.is_any_allowed(roles, 'view', resource)
    for resource in ['post', 'infor']:
        assert not acl.is_any_allowed(roles, 'view', resource)

    for resource in ['post', 'news', 'infor', 'event']:
        assert not acl.is_allowed('user', 'view', resource)
        assert acl.is_allowed('super', 'view', resource)
        assert acl.is_allowed('super', 'new', resource)
        assert acl.is_any_allowed(['user', 'super'], 'view', resource)

    # test 'new' operation
    roles = ['writer', 'editor']

    for role in roles:
        for resource in ['news', 'event']:
            assert acl.is_allowed(role, 'new', resource)
        for resource in ['post', 'infor']:
            assert not acl.is_allowed(role, 'new', resource)

    for resource in ['news', 'event']:
        assert acl.is_any_allowed(roles, 'new', resource)
    for resource in ['post', 'infor']:
        assert not acl.is_any_allowed(roles, 'new', resource)

    roles = ['user', 'manager']

    for role in roles:
        for resource in ['news', 'event', 'post', 'infor']:
            assert not acl.is_allowed(role, 'new', resource)
    for resource in ['news', 'event', 'post', 'infor']:
        assert not acl.is_any_allowed(roles, 'new', resource)


def test_deny(acl):
    # add allowed rule and denied rule
    acl.allow('actived_user', 'new', 'comment')
    acl.deny('manager', 'new', 'comment')

    # test allowed rules
    roles = ['actived_user', 'writer']

    for role in roles:
        assert acl.is_allowed(role, 'new', 'comment')

    assert acl.is_any_allowed(roles, 'new', 'comment')

    # test denied rules
    roles = ['manager', 'editor']

    for role in roles:
        assert not acl.is_allowed(role, 'new', 'comment')

    assert not acl.is_any_allowed(roles, 'new', 'comment')


def test_undefined(acl):
    # test denied undefined rule
    roles = ['user', 'actived_user', 'writer', 'manager', 'editor']

    for resource in ['comment', 'post', 'news', 'infor', 'event']:
        for role in roles:
            assert not acl.is_allowed(role, 'x', resource)
            assert not acl.is_allowed(role, '', resource)
            assert not acl.is_allowed(role, None, resource)
        assert not acl.is_any_allowed(roles, 'x', resource)
        assert not acl.is_any_allowed(roles, '', resource)
        assert not acl.is_any_allowed(roles, None, resource)

    # test `None` defined rule
    for resource in ['comment', 'post', 'news', 'infor', 'event', None]:
        for op in ['undefined', 'x', '', None]:
            assert acl.is_allowed('super', op, resource)


def test_assertion(acl):
    # set up assertion
    db = {'newsid': 1}

    def check(acl, role, operation, resource):
        return db['newsid'] == 10

    assertion = check

    # set up rules
    acl.add_role('writer2', parents=['writer'])
    acl.allow('writer', 'edit', 'news', assertion)
    acl.allow('manager', 'edit', 'news')

    # test while assertion is invalid
    assert not acl.is_allowed('writer', 'edit', 'news')
    assert not acl.is_allowed('writer2', 'edit', 'news')
    assert acl.is_allowed('manager', 'edit', 'news')
    assert acl.is_allowed('editor', 'edit', 'news')

    # test while assertion is valid
    db['newsid'] = 10
    assert acl.is_allowed('writer', 'edit', 'news')
    assert acl.is_allowed('editor', 'edit', 'news')
    assert acl.is_allowed('manager', 'edit', 'news')


def test_is_any_allowed(acl):
    pass  # TODO: create a test


def test_delete_role(acl):
    acl.add_role('nonspy')  # our control who should remain unaffected
    acl.allow('nonspy', 'view', 'news')
    acl.deny('nonspy', 'edit', 'news')

    acl.add_role('spy')
    acl.allow('spy', 'view', 'news')
    acl.deny('spy', 'edit', 'news')
    assert acl.is_allowed('spy', 'view', 'news')
    assert not acl.is_allowed('spy', 'edit', 'news')

    # oh no! we found a spy! remove them!
    acl.delete_role('spy')

    # as the role no longer exists it should raise an assertion
    with pytest.raises(AssertionError):
        assert not acl.is_allowed('spy', 'view', 'news')
    with pytest.raises(AssertionError):
        assert not acl.is_allowed('spy', 'edit', 'news')

    # as an extra check let's make sure we don't see any orphaned
    # rules for 'spy' in _allowed or _denied
    for rule_list in (acl._allowed, acl._denied):
        for rule in rule_list:
            assert rule[0] != 'spy'

    # nonspy should be unaffected by all this
    assert acl.is_allowed('nonspy', 'view', 'news')
    assert not acl.is_allowed('nonspy', 'edit', 'news')


def test_child_role_deletion(acl):
    
    # create unrelated parent and child
    acl.add_role('unrelated')
    acl.add_role('unrelated', ['spawn'])
    acl.allow('unrelated', 'view', 'news')
    assert 'unrelated' in str(acl._children)
    assert 'spawn' in str(acl._children)
    
    # create parent and child, that we care about
    acl.add_role('daddy')
    acl.allow('daddy', 'view', 'news')
    assert 'daddy' not in str(acl._children)
    acl.add_role('kiddo', ['daddy'])
    assert 'daddy' in str(acl._children)
    assert 'kiddo' in str(acl._children)
    assert acl.is_allowed('kiddo', 'view', 'news')
    
    # ensure we can't delete a father who has a dependent child
    with pytest.raises(AssertionError):
        acl.delete_role('daddy')
    
    # delete child role
    acl.delete_role('kiddo')
    assert 'kiddo' not in str(acl._children)
    assert acl.is_allowed('daddy', 'view', 'news')
    
    # ensure we CAN delete a father with no dependent children
    acl.delete_role('daddy')
    with pytest.raises(AssertionError):
        acl.is_allowed('daddy', 'view', 'news')
    
    # make sure those unrelated father and child remain
    assert 'unrelated' in str(acl._children)
    assert 'spawn' in str(acl._children)
    
    
    
    

def test_delete_role_with_child_roles_fails(acl):
    acl.add_role('nonspy')  # our control who should remain unaffected
    acl.allow('nonspy', 'view', 'news')
    acl.deny('nonspy', 'edit', 'news')

    acl.add_role('spy')
    acl.add_role('childspy', ['spy'])  # should prevent deletion
    acl.allow('spy', 'view', 'news')
    acl.deny('spy', 'edit', 'news')
    assert acl.is_allowed('spy', 'view', 'news')
    assert not acl.is_allowed('spy', 'edit', 'news')

    # as it has a child role it should assert
    with pytest.raises(AssertionError):
        acl.delete_role('spy')

    # nonspy should be unaffected by all this
    assert acl.is_allowed('nonspy', 'view', 'news')
    assert not acl.is_allowed('nonspy', 'edit', 'news')


def test_delete_role__check_deny_only_roles_also_removed(acl):
    acl.add_role('spy')
    acl.deny('spy', 'edit', 'news')  # a deny only role
    assert not acl.is_allowed('spy', 'edit', 'news')
    assert 'spy' in acl._denial_only_roles
    # oh no! we found a spy! remove them!
    acl.delete_role('spy')
    assert 'spy' not in acl._denial_only_roles
