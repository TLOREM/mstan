

"""
This here would ideally have a much better error system, with helpful messages
"""



class InvalidRequestError(Exception):
    """
    Invalid request, sent a project requirement file without the associated project data
    """

class ProjectAlreadyExistingError(Exception):
    """
    Trying to add a project that already exists
    """
    def __init__(self, *args):
        super().__init__(*args)


class UserAlreadyExistsError(Exception):
    """
    User already exists
    """

    def __init__(self, *args):
        super().__init__(*args)


class UserNotExistingError(Exception):
    """
    User doesn't exist
    """

    def __init__(self, *args):
        super().__init__(*args)


class ProjectNotExistingError(Exception):
    """
    Project doesn't exist
    """

    def __init__(self, *args):
        super().__init__(*args)

class DependencyNotExistingError(Exception):
    """
    Dependency doesn't exist
    """
    
    def __init__(self, *args):
        super().__init__(*args)

class DependencyVersionNotCheckedError(Exception):
    """
    Dependency info on this specific version hasn't been fetched
    """

    def __init__(self, *args):
        super().__init__(*args)


class ShouldBeImpossibleError(Exception):
    """
    Unreachable code was reached
    """

    def __init__(self, *args):
        super().__init__(*args)