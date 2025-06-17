# Build stage
FROM golang:1.22 as build

WORKDIR /app
COPY . .

RUN go build -o server ./cmd/server

# Run stage
FROM debian:bullseye-slim

WORKDIR /app
COPY --from=build /app/server .

EXPOSE 8080
CMD ["./server"]
