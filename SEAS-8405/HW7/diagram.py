from diagrams import Cluster, Diagram
from diagrams.programming.framework import Flask
from diagrams.onprem.network import Nginx
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.container import Docker
from diagrams.onprem.client import User

with Diagram(
    "Flask App Architecture in Docker",
    filename="architecture_diagram",
    outformat="png",
    show=False
):
    user = User("Local Browser")

    with Cluster("Host System"):
        docker = Docker("Docker Daemon")

        with Cluster("Docker Container: web"):
            nginx = Nginx("Nginx (port 15000)")
            flask = Flask("Flask App (port 5000)")
            nginx >> flask

        [docker, user] >> nginx