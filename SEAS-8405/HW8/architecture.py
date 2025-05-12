from diagrams import Diagram, Cluster
from diagrams.onprem.container import Docker
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.client import Users
from diagrams.onprem.compute import Server

with Diagram("IAM-Protected Flask App Architecture", show=True, direction="LR"):

    user = Users("Client")

    with Cluster("Docker Compose Network: iam_network"):

        with Cluster("Keycloak IAM"):
            keycloak = Docker("keycloak_iam")
            keycloak_db = PostgreSQL("keycloak_db")

        with Cluster("Flask App Stack"):
            flask_app = Docker("flask_protected_api")
            nginx = Docker("nginx (inside container)")
            gunicorn = Docker("gunicorn (inside container)")
            flask = Server("Flask App")

            flask_app >> [nginx, gunicorn, flask]

        # Internal connections
        keycloak >> keycloak_db
        flask_app >> keycloak

    # External interaction
    user >> flask_app