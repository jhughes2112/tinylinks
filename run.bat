@echo off
rem Use a throwaway docker volume for /data (bind mounts don't play well with the AOT alpine image on Windows).
rem It is created fresh on start and destroyed when the container exits, so no state survives between runs.
docker volume create tinylinks-data

start http://localhost:17777

docker run -it --rm  --name tinylinks -p 17777:17777 ^
  -v tinylinks-data:/data -w /data ^
  tinylinks:latest ^
  --log_config console,5 ^
  --conn_bindurl http://+:17777/ ^
  --advertise_urls http://localhost:17777/ ^
  --storage_config /data ^
  --static_root /app/static_root ^
  --session_duration 3600 ^
  --linkcreate_secret somelinksecrethere ^
  --auth_config always ^
  --client_config testclient,http://localhost:17777/

docker volume rm tinylinks-data
