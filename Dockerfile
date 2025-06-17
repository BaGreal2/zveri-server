# Build stage
FROM golang:1.24 as build

WORKDIR /app
COPY . .

# Adjust this path if your main.go is somewhere else
RUN go build -o server ./cmd/server

# Run stage
FROM debian:bullseye-slim

WORKDIR /app
COPY --from=build /app/server .
COPY users.db .

EXPOSE 8080
CMD ["./server"]
