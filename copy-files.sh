#!/bin/bash

docker cp ./cliente/. client:/app
docker cp ./servidor/. servidor:/app
docker cp ./roteador/. roteador:/app
docker cp ./badguy/. badguy:/app