from fastapi import FastAPI, File, UploadFile, Query, Form
from .osvQuery import fetchVulnerabilities
from .storage import *
from .utility import parseRequirements, setVulnerable

# As of Python 3.13, the GIL can be disabled using the --disable-gil, something to look into if searching for performance, 
#   it was experimental until very recently

# faster upload by going directly through starlette?


app = FastAPI()

userStorage = UserStore
depStorage = DepedencyStore # the two most difficult things in programming are cache invalidation, naming variables and off by one errors
vulnStorage = VulnerabilitiesStore

TestUser = "TestUser"

@app.get("/")
def root():
    return {
        "message": "Some value2",
        "goto:": "/request"}




@app.post('/application')
def create_application(
    username:       Annotated[str, Query(description="Username")] = TestUser,
    projectName:    Annotated[str, Form(description="Project's Name")] = None,
    projectDescription:    Annotated[str, Form(description="Project's description, ignored if not during project creation")] = None,
    reqFile:        Annotated[UploadFile, File(description="A requirements file")] = None,
    ):
    """
    #1: user + project + req = create
    #2  user + project = get project specific
    #3: user = get all
    # """
    if reqFile and not projectName: # could go down below to avoid a double check, but the cost is minimal vs readability
        # This could be trivialized/made impossible by using a single class union in the parameters, but it might just add confusion
        raise InvalidRequestError(f"cannot upload a requirement file by itself without attaching it to a project (name)")

    if reqFile:
        # a lot more file validation to be done here to avoid malicious/broken issues
        if reqFile.content_type != "text/plain":
            raise InvalidRequestError("Requirement file needs to be a text file")
        deps = parseRequirements(reqFile)
        # this is a symptom of a lack of fastAPI knowledge, though it looks like it might  be an HTTP limitation
        userStorage.add(username, Project(name=projectName, description=projectDescription, dependencies=deps))
        return {"message":f"User {username} now has project {projectName}"}

    if projectName: #get specific project
        project:Project = userStorage.get(username, projectName)
        fetchVulnerabilities([project])
        
        if not project.vulnerable:
            return {"Vulnerabilities":[]} # could return safe or something else
        
        vulnDeps = []
        for depName, depVersion in project.dependencies.items():
            vulnDeps.append({depName:{
                "version":depVersion,
                "indetifier":f"{depName}=={depVersion}",
                "vulnerabilities":[
                    id for id in DepedencyStore.get(depName, depVersion)
                ]
                }
            })

        return {"result":vulnDeps}

    projects:dict[str, Project] = userStorage.get(username) #gets all

    appStatus = []
    fetchStatus = []
    for _, project in projects.items(): 
        if project.vulnerable is None and setVulnerable(project) is None:
            fetchStatus.append(project)
            continue
        appStatus.append({project.name:{"Vulnerable":project.vulnerable}})
    

    fetchVulnerabilities(fetchStatus)

    for project in fetchStatus:
        if project.vulnerable is None:
            raise ShouldBeImpossibleError("This should be impossible #1")
        appStatus.append({project.name:{"Vulnerable":project.vulnerable}})
    return { "result":appStatus }

    return userStorage.add(DefaultUser, ProjectBase, data)


@app.post("/dependency")
def checkVuln(username:       Annotated[str, Query(description="Username")] = TestUser,
              dependency:    Annotated[str, Form(description="A dependency", pattern="^\w+==.{1,10}$")] = None):
    """
    #1: user + dependency
    #2  user 
    """
    if dependency:
        dep = dependency.lower().split("==", 1)
        # do in-memory editing instead of this copy-fest
        depName, depVersion = dep[0], dep[1].strip()
        # This is very dirty, but it wouldn't really affect speed and a bogus project makes everything much neater
        fetchVulnerabilities([Project(name="", description="", dependencies={depName:depVersion})])

        projects:dict[str, Project] = UserStore.get(username)
        
        
        print(f"{depName}=+={depVersion}")
        print(projects)
        
        pjList = []
        for project in projects.values():
            if project.dependencies.get(depName) == depVersion:
                pjList.append(project.name)
        
        return { "result": {
            "usedIn":pjList,
            "vulnerabilities": [
                vulnStorage.get(id) for id in depStorage.get(depName, depVersion)
            ]
        }}
    
    
    # get all projects
    projects:dict[str, Project] = UserStore.get(username)
    fetchVulnerabilities(projects.values())
    dependencySet = set()
    for project in projects.values():
        if project.vulnerable is None:
            raise ShouldBeImpossibleError("Should be impossible #3")
        if project.vulnerable: #else no dependency with vulnerabilities
            dependencySet.update(project.dependencies.items())

    return {"result":[{f"{depName}=={depVersion}": "vulnerable" if depStorage.isVulnerable(depName, depVersion) else "safe" }
                      for depName, depVersion in dependencySet]}

    