from __future__ import absolute_import

import itertools

__all__ = ["Registry"]

RULE_ROLE_NAME_TUPLE_INDEX = 0


class Registry(object):
    """The registry of access control list."""

    def __init__(self):
        self._roles = {}
        self._resources = {}
        self._allowed = {}
        self._denied = {}
        self._children = {}

    def add_role(self, role, parents=[]):
        """Add a role or append parents roles to a special role."""

        add_as_set_item(
            dictionary=self._roles,
            key=role,
            item_or_items=parents
        )

        for parent in parents:
            add_as_set_item(
                dictionary=self._children,
                key=parent,
                item_or_items=role
            )

    def remove_role_from_parent(self, role, parent):
        """Removes a child role which has been added to a parent"""

        self._children = remove_set_item_and_empty_dict_items(
            dictionary=self._children,
            key=parent,
            set_item_to_remove=role
        )

        self._roles = remove_set_item_and_empty_dict_items(
            dictionary=self._roles,
            key=role,
            set_item_to_remove=parent
        )

    def delete_role(self, role):
        assert role not in self._children, 'Cannot delete a role with children'
        # can delete children themselves, just not parents

        # remove all rules that mention this role
        self._allowed = {
            k: v for k, v in self._allowed.items() if k[RULE_ROLE_NAME_TUPLE_INDEX] != role
        }
        self._denied = {
            k: v for k, v in self._denied.items() if k[RULE_ROLE_NAME_TUPLE_INDEX] != role
        }

        self._children = remove_child_role(
            existing_children=self._children,
            role_to_remove=role
        )

        # now remove the role
        del self._roles[role]

    def add_resource(self, resource, parents=[]):
        """Add a resource or append parents resources to a special resource."""
        add_as_set_item(self._resources, resource, parents)

    def remove_resource(self, resource_to_remove, parent_of_resource=None):
        """Add a resource or append parents resources to a special resource."""

        if parent_of_resource is not None:
            self._resources[parent_of_resource] = filter_set_item(
                existing_set=self._resources[parent_of_resource],
                set_item_to_remove=resource_to_remove
            )

        del self._resources[resource_to_remove]

    def allow(self, role, operation, resource, assertion=None):
        """Add an allowed rule.

        The added rule will allow the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._allowed[role, operation, resource] = assertion

    def remove_allow(self, role, operation, resource):
        """Removes an allowed rule"""
        del self._allowed[role, operation, resource]

    def deny(self, role, operation, resource, assertion=None):
        """Add a denied rule.

        The added rule will deny the role and its all children roles to
        operate the resource.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources
        self._denied[role, operation, resource] = assertion

    def remove_deny(self, role, operation, resource):
        """Removes a denied rule"""
        del self._denied[role, operation, resource]

    def is_allowed(self, role, operation, resource, check_allowed=True,
                   **assertion_kwargs):
        """Check the permission.

        If the access is denied, this method will return False; if the access
        is allowed, this method will return True; if there is not any rule
        for the access, this method will return None.
        """
        assert not role or role in self._roles
        assert not resource or resource in self._resources

        roles = set(get_family(self._roles, role))
        operations = {None, operation}
        resources = set(get_family(self._resources, resource))

        def DefaultAssertion(*args, **kwargs):
            return True

        is_allowed = None
        default_assertion = DefaultAssertion

        for permission in itertools.product(roles, operations, resources):
            if permission in self._denied:
                assertion = self._denied[permission] or default_assertion
                if assertion(self, role, operation, resource,
                             **assertion_kwargs):
                    return False  # denied by rule immediately

            if check_allowed and permission in self._allowed:
                assertion = self._allowed[permission] or default_assertion
                if assertion(self, role, operation, resource,
                             **assertion_kwargs):
                    is_allowed = True  # allowed by rule

        return is_allowed

    def is_any_allowed(self, roles, operation, resource, **assertion_kwargs):
        """Check the permission with many roles."""
        is_allowed = None  # no matching rules
        for i, role in enumerate(roles):

            check_allowed = not is_allowed

            # if another role gave access,
            # don't bother checking if this one is allowed
            is_current_allowed = self.is_allowed(role, operation, resource,
                                                 check_allowed=check_allowed,
                                                 **assertion_kwargs)
            if is_current_allowed is False:
                return False  # denied by rule
            elif is_current_allowed is True:
                is_allowed = True
        return is_allowed


def add_as_set_item(dictionary, key, item_or_items):
    """Makes adding to a dictionary of sets a single call"""
    if key not in dictionary:
        dictionary[key] = set()
    if isinstance(item_or_items, list):
        dictionary[key].update(item_or_items)
    else:
        dictionary[key].add(item_or_items)


def filter_set_item(existing_set, set_item_to_remove):
    filtered_set = set([item for item in existing_set if item != set_item_to_remove])
    return filtered_set


def remove_set_item_and_empty_dict_items(dictionary, key, set_item_to_remove):
    """The opposite of add_as_set_item"""
    new_dictionary = {k: v for (k, v) in dictionary.items() if k != key}

    existing_set = dictionary[key]
    assert isinstance(existing_set, set)
    new_children = filter_set_item(existing_set, set_item_to_remove)

    if len(new_children) > 0:
        new_dictionary[key] = new_children

    return new_dictionary


def get_family(all_parents, current):
    """Iterate current object and its all parents recursively."""
    yield current
    for parent in get_parents(all_parents, current):
        yield parent
    yield None


def get_parents(all_parents, current):
    """Iterate current object's all parents."""
    for parent in all_parents.get(current, []):
        yield parent
        for grandparent in get_parents(all_parents, parent):
            yield grandparent


def remove_child_role(existing_children, role_to_remove):
    """
    Filters a given role from a child roles dictionary,
    expects dict of parent roles, with sets of children,
    and returns pruned dictionary copy
    """
    pruned_children = {}  # start with empty dict, which we'll add to
    for parent in existing_children:
        if parent != role_to_remove:
            new_children = filter_set_item(existing_children[parent], role_to_remove)
            if len(new_children) > 0:
                pruned_children[parent] = new_children
    return pruned_children
