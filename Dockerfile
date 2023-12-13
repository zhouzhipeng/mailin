FROM rust:latest as build-env
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
EXPOSE 8025
COPY --from=build-env /app/target/release/mailin-server /
CMD ["./mailin-server","--address","0.0.0.0:8025"]
