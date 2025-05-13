from diagrams import Diagram, Cluster, Edge
from diagrams.programming.framework import Flask
from diagrams.onprem.network import Nginx
from diagrams.onprem.container import Docker
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.client import Users
from diagrams.custom import Custom

with Diagram("IAM-Protected Flask App Architecture", 
             filename="./deliverables/architecture_diagram",
             outformat="png",
             show=False,
             direction="LR"):

    user = Users("Client")

    with Cluster("Docker Compose Network: iam_network"):

        with Cluster("Keycloak IAM"):
            keycloak = Custom("keycloak_iam", "./icons/Keycloak.png")
            keycloak_db = PostgreSQL("keycloak_db")

        with Cluster("Flask App Stack"):
            flask_app = Docker("flask_protected_api")
            nginx = Nginx("Nginx (port 5000)")
            flask = Flask("Flask App (port 5050)")

            nginx >> Edge() << flask_app >> Edge() << flask

        keycloak >> Edge() << keycloak_db
        flask_app >> Edge() << keycloak

    user >> Edge() << nginx