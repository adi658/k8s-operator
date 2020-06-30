#!/bin/bash

cd /data/eks-cluster/operator/op3

# Clean up
echo "" 
echo "--------- Clean Up ---------"
kubectl delete -f . 
kubectl delete secret my-secret-1
kubectl delete secret my-secret-2
kubectl delete secret my-secret-3

echo "" 
echo "--------- Check if secret is present ---------"
kubectl get secret sectigo-secret
sleep 3

echo "" 
echo "--------- Build Docker image ---------"
docker image build -t adi658/op3:latest .
docker image push adi658/op3:latest

echo "" 
echo "--------- Apply deployment file and show pods ---------"
kubectl apply -f .

echo "" 
echo "--------- Waiting 5 secs ---------"
sleep 5

echo "" 
echo "--------- Show Pods ---------"
kubectl get pods

echo "" 
echo "--------- Waiting 5 secs ---------"
sleep 5 

echo "" 
echo "--------- Check if secret is updated ---------"
kubectl get secret 

echo "END"