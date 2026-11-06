# One Dockerfile for all three Go services. Pick one with a build argument:
#   docker build --build-arg SERVICE=auth-server -t oauth-demo/auth-server .
# compose.yaml builds and runs all of them together.
ARG SERVICE=auth-server

# --- Build stage: compile a static Go binary ---
FROM golang:1.27-alpine AS build
ARG SERVICE
WORKDIR /src

# Download dependencies first, so they're cached when only code changes.
COPY ${SERVICE}/go.mod ${SERVICE}/go.sum ./
RUN go mod download

COPY ${SERVICE}/ ./
# CGO off gives a fully static binary. HTML templates are embedded in it.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app .

# --- Runtime stage: just the binary, no shell, running as a non-root user ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
