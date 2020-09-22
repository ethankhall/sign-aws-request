FROM rust:1.46 as builder

RUN USER=root cargo new --bin sign-aws-request
WORKDIR /sign-aws-request
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/release/deps/sign_aws_request*
RUN cargo build --release

# Verify that the CLI is accessable
RUN /sign-aws-request/target/release/sign-aws-request serve --help

FROM debian:buster-slim
ARG APP=/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 3000

ENV TZ=Etc/UTC \
    APP_USER=appuser

ENV TINI_VERSION v0.18.0

ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /sign-aws-request/target/release/sign-aws-request ${APP}/sign-aws-request

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

ENTRYPOINT ["/tini", "--"]
CMD [ "./sign-aws-request"]