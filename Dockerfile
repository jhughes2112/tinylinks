# Stage 1: Build the backend as a NativeAOT binary (needs clang + musl toolchain on alpine)
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
RUN apk add --no-cache clang build-base zlib-dev
WORKDIR /source
COPY server/. .
RUN dotnet publish --nologo -c Release -o /output -r linux-musl-x64 TinyLinks.csproj

# Stage 2: Create the runtime image. runtime-deps only (no .NET runtime) since the binary is self-contained native code.
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine AS runtime
WORKDIR /app
COPY --from=build /output /app
COPY static_root/. /app/static_root
# /data is pre-created and chowned so a fresh named volume mounted there inherits noprivileges ownership.
RUN adduser --disabled-password --home /app --gecos '' noprivileges && chown -R noprivileges /app && mkdir /data && chown noprivileges /data && ls -al /app
USER noprivileges
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ENTRYPOINT ["/app/TinyLinks"]
