FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev make pkgconf xxd \
      libpq-dev openssl-dev openssl-libs-static
WORKDIR /src
COPY Makefile db.h db.c ws_chat64k.c ./
COPY public/index.html ./public/index.html
# Embed frontend as C array.
RUN xxd -i public/index.html > bundled.h \
 && sed -i 's/public_index_html/INDEX_HTML/g' bundled.h \
 && gcc -O2 -Wall -Wextra -static \
      -I/usr/include/postgresql -I. \
      -o ws_chat64k ws_chat64k.c db.c \
      $(pkg-config --libs --static libpq) \
 && strip ws_chat64k

FROM scratch
COPY --from=build /src/ws_chat64k /ws_chat64k
ENV PORT=5555
EXPOSE 5555
ENTRYPOINT ["/ws_chat64k"]
