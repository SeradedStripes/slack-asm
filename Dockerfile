FROM alpine:latest AS build

RUN apk add --no-cache nasm binutils make

COPY . /app
WORKDIR /app

RUN make slack

FROM scratch

COPY --from=build /app/slack /slack

ENTRYPOINT ["/slack"]
