This repo contains the infrastructure necesary to deploy https TDX applications.

This project has several components:

docker_compose.yml - A docker composer for the VM deployment, using traefik as the main image.

attestd - An attestation service used to attest the server's ssl certificates.

echo - A simple example application docker image - echo service

client/browser - An https client for browser clients, that virtualizes https to confirm the main client is using an https connection to the right certificate.Echo response: 

client/native - A client for native clients, that manually downloads the ssl certificate, attests it, and then pins it for connections. 


# How to use

1) Edit start.sh settings.

2) Create a TDX-VM that simply runs start.sh.

3) Run the example client. If the infrastructure is working it will output "Echo response: hello".
