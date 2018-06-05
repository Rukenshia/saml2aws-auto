all:
	docker build -t ruken/x86_64-unknown-linux-gnu -f Dockerfile_x86_64-unknown-linux-gnu .
	docker build -t ruken/x86_64-unknown-linux-musl -f Dockerfile_x86_64-unknown-linux-musl .
	docker push ruken/x86_64-unknown-linux-gnu
	docker push ruken/x86_64-unknown-linux-musl