#!/bin/bash

cd /data/eks-cluster/operator/op3

# Clean up
echo "" 
echo "--------- Clean Up ---------"
kubectl delete -f deploy/. 

# echo "" 
# echo "--------- Check if secret is present ---------"
# kubectl get secret sectigo-secret
# sleep 3

echo "" 
echo "--------- Build Docker image ---------"
docker image build -t adi658/op3:latest -f Dockerfile .
docker image push adi658/op3:latest

echo "" 
echo "--------- Build Docker image for Renew ---------"
docker image build -t adi658/op3:renew -f Dockerfile_renew .
docker image push adi658/op3:renew

echo "" 
echo "--------- Apply deployment file and show pods ---------"
kubectl apply -f deploy/.

sleep 2

echo "" 
echo "--------- Show Pods ---------"
kubectl get pods

sleep 2

echo "" 
echo "--------- Show secrets ---------"
kubectl get secret 

echo "END"