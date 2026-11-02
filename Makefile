BINARY := bin/anti-spam-bot
SERVICE_NAME := anti-spam-bot.service

.PHONY: build test validate install-service restart status logs clean

build:
	GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/bot

test:
	GOTOOLCHAIN=local go test -v ./...

validate: build
	./$(BINARY) -config config.yaml -validate

install-service: build
	sudo cp deploy/$(SERVICE_NAME) /etc/systemd/system/$(SERVICE_NAME)
	sudo systemctl daemon-reload
	sudo systemctl enable --now $(SERVICE_NAME)
	sudo systemctl status $(SERVICE_NAME) --no-pager

restart: build
	sudo systemctl restart $(SERVICE_NAME)
	sudo systemctl status $(SERVICE_NAME) --no-pager

status:
	sudo systemctl status $(SERVICE_NAME) --no-pager

logs:
	sudo journalctl -u $(SERVICE_NAME) -f

clean:
	rm -rf bin/
