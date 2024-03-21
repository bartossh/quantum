.PHONY: server
server:
	cd server
	cargo build --release

.PHONY: client
client:
	cd client
	cargo build --release


