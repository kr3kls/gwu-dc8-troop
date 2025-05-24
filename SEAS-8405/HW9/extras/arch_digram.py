from diagrams import Diagram, Cluster
from diagrams.onprem.compute import Server
from diagrams.onprem.client import Users
from diagrams.programming.language import Java

with Diagram("Log4Shell Exploit Architecture",
             filename="../deliverables/architecture_diagram",
             outformat="png",
             show=False,
             direction="LR"):

    attacker = Users("Attacker")

    with Cluster("Docker Container"):
        spring_app = Java("Vulnerable Java App")

    with Cluster("Host Machine"):
        ldap_server = Server("LDAP Server")

    attacker >> spring_app
    spring_app >> ldap_server