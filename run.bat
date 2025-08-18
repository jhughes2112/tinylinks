start http://localhost:7777

docker run -it --rm  --name tinylinks -p 7777:7777 ^
  -v %cd%/data:/data -w /data ^
  dev.reachablegames.com/tinylinks:latest