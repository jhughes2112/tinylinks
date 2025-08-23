start http://localhost:17777

docker run -it --rm  --name tinylinks -p 17777:17777 ^
  -v %cd%/data:/data -w /data ^
  tinylinks:latest ^
  --log_config console,5 ^
  --conn_bindurl http://+:17777/ ^
  --advertise_urls http://localhost:17777/ ^
  --storage_config /data ^
  --static_root /app/static_root ^
  --session_duration 3600 ^
  --linkcreate_secret somelinksecrethere ^
  --auth_config always