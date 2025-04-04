from pydantic import BaseModel
from typing import Annotated
from .customErrors import *


"""
Trivial storage with some redudancy for simplicity's sake


But ideally we'd want multi-level caches
    an in-memory cache, with a WAL on disk and finally a remote host

I didn't limit any of the in-memory storage, some MTF algorithm would probably be something to add too

"""

class Project(BaseModel):
    name: Annotated[str, "Project's name"] 
    description: Annotated[str, "Project's description"] = ""
    dependencies: Annotated[dict[str, str], "Project's dependency dict, dict[name, version]"] = {}
    vulnerable: Annotated[bool|None, "Cached value of if the app is vulnerable, None means not checked yet"] = None
    # a list might be faster here depending on average size

class User(BaseModel):
    username: Annotated[str, "User's username"]
    projects: Annotated[dict[str, Project], "A dict of all the user's projects [ProjectName, Project]"] = {}

class Dependency(BaseModel):
    name:Annotated[str, "Dependency name"]
    vulnerabitilities: Annotated[dict[str, list[str]], "Dict of [version, list[Ids], where Ids are the vulnerability ids]"] = {}

Vulnerabilities = Annotated[dict[str, dict], "Dictionary of vulnerabilities where [ID, info]"]


class UserStore():
    _mem: Annotated[dict[str, User], "Dict of [username, user]"] = {}

    @staticmethod
    def add(username: Annotated[str, "User's username/ID"], 
            project: Annotated[Project, "Project to be added, None if only adding user"] = None):
        mem = UserStore._mem #assuming this just creates a reference
        if username not in mem:
            mem[username] = User(username=username)
        elif not project:
            raise UserAlreadyExistsError(f"Username {username} is already taken")

        if project:
            usr = mem[username]
            if project.name not in usr.projects:
                usr.projects[project.name] = project
            else:
                raise ProjectAlreadyExistingError(f"Project {project.name} already exists")

    
    @staticmethod
    def get(username: Annotated[str, "User's username/ID"],
            projectName: Annotated[str, "Project name if a specific project, None if all the projects"] = None) -> list[Project]:
        """ Will return a list of projects regardless for simplicity """
        mem = UserStore._mem

        usr = mem.get(username)
        if not usr:
            raise UserNotExistingError("User doesn't exist")
        
        if not projectName: # get all projects
            return usr.projects
        
        #get a specific project
        project = usr.projects.get(projectName)
        if not project:
            raise ProjectNotExistingError("Project doesn't exist")
        return project
        

class DepedencyStore():
    _mem: Annotated[dict[str, Dependency], "Dict of [dependencyName, Dependency]"] = {}

    @staticmethod
    def add(depName:str, version:str, vulnList:list = []): # name, version, vulnerability list
        """ This method can overwrite an existing entry to update, returns the added depedency"""
        mem = DepedencyStore._mem

        dep = mem.get(depName)
        if dep:
            dep.vulnerabitilities[version] = vulnList
            return
        
        
        mem[depName] = Dependency(name=depName, vulnerabitilities={version:vulnList})
        return mem[depName]
        # need a version/vuln aggegation mechanism, maybe a trie? TBD
        


    @staticmethod
    def get(depName:str, version:str = None) -> list[str]:
        mem = DepedencyStore._mem
        
        dep = mem.get(depName)
        if not dep:
            raise DependencyNotExistingError("Dependency does't exist")
        if version is None:
            return dep.vulnerabitilities 
        vulns = dep.vulnerabitilities.get(version)
        if vulns is None:
            raise DependencyVersionNotCheckedError("Dependency exists, but version vulnerabilities were never fetched")
        return vulns
    
    @staticmethod
    def isVulnerable(depName:str, version:str) -> bool:
        """ True/False if known, None otherwise"""
        mem = DepedencyStore._mem
        dep = mem.get(depName)
        if not dep:
            return None
        vulns = dep.vulnerabitilities.get(version)
        if vulns is None:
            return None
        return False if vulns == [] else True
        
        

class VulnerabilitiesStore():
    _mem: Vulnerabilities = {}

    @staticmethod
    def get(id:str):
        """ KeyError if it doesn't exists, we'd ideally customize the error like the above """
        return VulnerabilitiesStore._mem[id]
    
    @staticmethod
    def add(id:str, vulnerability:dict):
        """ This one also overwrites """
        VulnerabilitiesStore._mem[id] = vulnerability
