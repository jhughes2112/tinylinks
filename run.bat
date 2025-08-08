echo YOU MUST RUN THESE OR TESTS WILL FAIL
echo mkdir -p touch internal/assets/dist/
echo touch internal/assets/dist/placeholder.txt
docker run --rm -it -v %cd%:/workspace -w /workspace golang:alpine /bin/sh