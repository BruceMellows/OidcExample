#!/bin/sh
export $(grep -v '^#' .host.env | xargs)
go run main.go
