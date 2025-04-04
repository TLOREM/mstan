from typing import Annotated
from .storage import Project, Dependency, DepedencyStore, VulnerabilitiesStore
from .utility import setVulnerable
import requests
import json
import asyncio


OsvUrlSingle = "https://api.osv.dev/v1/query"
OsvUrlBatch = "https://api.osv.dev/v1/querybatch"
OsvUrlVulnId = "https://api.osv.dev/v1/vulns/"

BatchReply = dict # just an alias

def fetchVulnerabilities(projects:Annotated[list[Project], "List of projects to fetch missing vulnerabilities and updates accordingly"]):
    """
    Fetch missing vulnerabilities 
    """
    fetchList = []
    seen = set()
    for project in projects:
        for depName, depVersion in project.dependencies.items():
            t = (depName, depVersion)
            if t in seen:
                continue
            seen.add(t)
            if DepedencyStore.isVulnerable(depName, depVersion) is None: #could add a pending here instead of a seen
                fetchList.append({"version": depVersion, 
                                "package": { 
                                    "name" : depName,
                                    "ecosystem": "PyPI"
                                }
                            })

    if len(fetchList) != 0:
        _OsvRequest.fetchRemoteOsv(fetchList)

    for project in projects:
        setVulnerable(project) # to be changed for enumerate(projects) above @L22



class _OsvRequest(object):

    @staticmethod
    def fetchRemoteOsv(fetchList:list[dict]):
        if len(fetchList) == 1:
            resp = requests.post(OsvUrlSingle, json.dumps(fetchList[0])).json()
            
            dep:Dependency = DepedencyStore.add(fetchList[0]["package"]["name"], fetchList[0]["version"])
            if resp != {}:
                for vuln in resp["vulns"]:
                    VulnerabilitiesStore.add(vuln["id"], vuln)

                dep.vulnerabitilities[fetchList[0]["version"]] = [vuln["id"] for vuln in resp["vulns"]]
            return {"results": [resp]} # simplicity even if not optimal, but mostly meaningless compared to fetch time
        
        # batch fetch

        data = json.dumps({"queries":fetchList})
        resp:BatchReply = requests.post(OsvUrlBatch, data).json()

        for i, pack in enumerate(resp["results"]):
            vulns = pack.get("vulns")
            
            DepedencyStore.add(fetchList[i]["package"]["name"], 
                                   fetchList[i]["version"], 
                                   [v["id"] for v in vulns] if vulns else []
                                   )
            

        vrep =  asyncio.run(_OsvRequest.fetchVulnByIds(resp))

        for vuln in vrep:
            VulnerabilitiesStore.add(vuln["id"], vuln)
            
        return resp
    
    @staticmethod
    async def fetchVulnByIds(resp:BatchReply): 
        async def _fetchById(id:str):
            return requests.get(f"{OsvUrlVulnId}{id}").json()
        packs = resp["results"]
        reqs = set()
        for pack in packs:
            if pack.get("vulns") is None:
                continue
            for vuln in pack["vulns"]:
                print(f"FETCHING:  {OsvUrlVulnId}{vuln["id"]}")
                reqs.add(asyncio.create_task(_fetchById(vuln["id"])))

        return await asyncio.gather(*reqs)

""" Sample reply to batch

{
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-7rjr-3q55-vv33"
                },
                {
                    "id": "GHSA-jfh8-c2jp-5v3q"
                },
                {
                    "id": "GHSA-p6xc-xr62-6r2g"
                },
                {
                    "id": "GHSA-vwqq-5vrc-xw9h"
                }
            ]
        },
        {}
    ]
}"""