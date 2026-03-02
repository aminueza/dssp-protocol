FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o dssp-gateway .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/dssp-gateway /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["dssp-gateway"]
