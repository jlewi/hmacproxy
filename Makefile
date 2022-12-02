build-dir:
	mkdir -p .build

build-go: build-dir
	CGO_ENABLED=0 go build -o .build/hmacproxy github.com/jlewi/hmacproxy

tidy-go:
	gofmt -s -w .
	goimports -w .
	
lint-go:
	# golangci-lint automatically searches up the root tree for configuration files.
	golangci-lint run

test-go:
	go test -v ./...

build-image-submit:
	COMMIT=$$(git rev-parse HEAD) && \
	    gcloud builds submit --project=$(GCPPROJECT) --async --config=cloudbuild.yaml \
	    --substitutions=COMMIT_SHA=local-$${COMMIT} \
	    --format=yaml > .build/gcbjob.yaml

build-image-logs:
	JOBID=$$(yq e ".id" .build/gcbjob.yaml) && \
		gcloud builds log --stream $${JOBID}

build-image: build-dir build-image-submit build-image-logs