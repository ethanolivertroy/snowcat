# Copyright 2021-2025 Praetorian Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.23.0 AS build
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOEXPERIMENT=loopvar go build -trimpath -ldflags="-s -w" -o snowcat ./cmd/snowcat

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 snowcat
USER 10001
VOLUME /data
COPY --from=build --chown=10001:10001 /app/snowcat /bin/
ENTRYPOINT ["/bin/snowcat"]
