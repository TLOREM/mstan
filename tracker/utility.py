from .storage import Project, DepedencyStore

def parseRequirements(reqFile) -> dict:
    """
    Parses a requirements.txt file
    """
        # extract to list or dict of some kind, doing dict here for simplicity
    data:dict[str, str] = {}


    # data validation needed here
    for req in reqFile.file: #assumes 1 req per line as in pip>freeze
        dep = req.split(b"==", 1) #this could create "maybe" could be an issue since python defaults to unicode, this is binary
        # do in-memory editing instead of this copy-fest for the line below
        data[str(dep[0], 'utf-8').lower()] = str(dep[1].strip(), 'utf-8')
    return data



def setVulnerable(project:Project) -> bool|None:
    """
    Check if it's vulnerable, if found set it in the project, if unsure, None
    """

    unkown = False
    for depName, depVersion in project.dependencies.items():
        vulnerable = DepedencyStore.isVulnerable(depName, depVersion)
        
        if vulnerable:
            project.vulnerable = True
            return True
        if vulnerable is None:
            unkown = None
        

    return unkown