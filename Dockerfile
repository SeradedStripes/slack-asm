FROM alpine:latest AS build

RUN apk add --no-cache nasm binutils

COPY *.asm /src/
WORKDIR /src

RUN nasm -f elf64 -o slack.o slack.asm && \
    ld -o slack slack.o

FROM scratch

COPY --from=build /src/slack /slack

ENTRYPOINT ["/slack"]
