FROM golang:1.22-alpine
RUN apk add gcompat
WORKDIR /app
ADD     . .
RUN     go build . 