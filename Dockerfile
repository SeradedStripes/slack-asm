FROM alpine:latest AS build

RUN apk add --no-cache nasm binutils

COPY *.asm /src/
WORKDIR /src

RUN for f in ./*.asm; do nasm -f elf64 -o "${f%%.asm}.o" "$f"; done && \
    ld -o slack ./*.o

FROM scratch

COPY --from=build /src/slack /slack

ENTRYPOINT ["/slack"]
