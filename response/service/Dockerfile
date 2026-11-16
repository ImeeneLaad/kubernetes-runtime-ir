# ir-responder: HTTP API in front of response/ir_respond.py, called by the SOAR.
# Build/run: bash response/service/run.sh
#
# No package manager runs during the build (apk/apt mirrors were 80 KB/s here):
#  - python:3.12-slim (Debian): python3, bash, coreutils, tar, gzip already present
#  - docker CLI copied from the official docker:29.8.1-cli image (= engine version),
#    needed for node-level actions (evidence from /proc + upperdir, conntrack flush)
#  - kubectl copied by run.sh from the kind node itself: exactly the cluster
#    version (v1.34.0), so no download and no version skew
FROM docker:29.8.1-cli AS dockercli

FROM python:3.12.14-slim-bookworm
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY bin/kubectl /usr/local/bin/kubectl

# The project is mounted read-only at /work, evidence/ read-write (see run.sh):
# the image contains no project code or secrets of its own.
WORKDIR /work
EXPOSE 8088
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python3", "-I", "/work/response/service/server.py"]
