FROM docker.io/library/golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warden-server .

FROM gcr.io/distroless/static-debian12
WORKDIR /app

COPY --from=build /out/warden-server /app/warden-server

EXPOSE 8080

ENTRYPOINT ["/app/warden-server"]
